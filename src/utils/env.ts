/**
 * Environment detection and cross-runtime crypto abstraction.
 * Supports Node.js ≥18, modern browsers (Web Crypto), and edge runtimes
 * (Cloudflare Workers, Vercel Edge, Deno) that expose the Web Crypto API.
 */

import { EncryptixError } from './errors.js';

export type RuntimeEnv = 'node' | 'browser' | 'edge' | 'unknown';

function detectRuntime(): RuntimeEnv {
  // Node.js
  if (typeof process !== 'undefined' && process.versions?.node) return 'node';
  // Browser
  if (typeof window !== 'undefined' && typeof window.crypto !== 'undefined') return 'browser';
  // Edge (Cloudflare Workers, Deno, etc.)
  if (typeof globalThis !== 'undefined' && typeof (globalThis as any).crypto !== 'undefined') return 'edge';
  return 'unknown';
}

export const RUNTIME: RuntimeEnv = detectRuntime();

/**
 * Returns the platform's crypto object.
 * - Node.js:  `require('crypto').webcrypto` (available since Node 15, stable 18+)
 * - Browser:  `window.crypto`
 * - Edge:     `globalThis.crypto`
 */
export function getCrypto(): Crypto {
  if (RUNTIME === 'node') {
    // Node 18+ has globalThis.crypto
    if (typeof globalThis.crypto !== 'undefined') return globalThis.crypto as Crypto;
    // Fallback for older Node builds
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require('crypto');
    return nodeCrypto.webcrypto as Crypto;
  }
  if (typeof globalThis.crypto !== 'undefined') return globalThis.crypto as Crypto;
  if (typeof window !== 'undefined' && window.crypto) return window.crypto;
  throw new Error('No crypto implementation found in this environment.');
}

/**
 * Returns Node's native `crypto` module only when running in Node.
 * Used for algorithms not yet in Web Crypto (e.g. hkdfSync, createHash).
 */
export async function getNodeCrypto(): Promise<typeof import('crypto') | null> {
  if (RUNTIME !== 'node') return null;
  try {
    // Dynamic import works in both ESM and CJS via the interop
    const mod = await import('crypto');
    return mod.default ?? mod;
  } catch {
    return null;
  }
}

/** Encode a string to Uint8Array via TextEncoder (available everywhere) */
export const encode = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Decode a Uint8Array to string via TextDecoder */
export const decode = (b: Uint8Array): string => new TextDecoder().decode(b);

type NodeTimingSafeEqual = (a: Uint8Array, b: Uint8Array) => boolean;
let nativeTimingSafeEqual: NodeTimingSafeEqual | null | undefined;

/**
 * Synchronously resolves Node's native `crypto.timingSafeEqual` without a
 * top-level `node:crypto` import (which would break browser/edge bundles).
 *
 * - `process.getBuiltinModule` (Node ≥20.16 / ≥22.3) works in both ESM and CJS.
 * - `require` covers the CJS build on older Node versions.
 * - Anything else (browsers, edge runtimes, ESM on old Node) returns null and
 *   callers use the constant-time JS fallback.
 *
 * The lookup is cached after the first call.
 */
function getNativeTimingSafeEqual(): NodeTimingSafeEqual | null {
  if (nativeTimingSafeEqual !== undefined) return nativeTimingSafeEqual;
  nativeTimingSafeEqual = null;
  if (RUNTIME !== 'node') return nativeTimingSafeEqual;
  try {
    const proc = process as unknown as { getBuiltinModule?: (id: string) => unknown };
    let mod: { timingSafeEqual?: NodeTimingSafeEqual } | undefined;
    if (typeof proc.getBuiltinModule === 'function') {
      mod = proc.getBuiltinModule('node:crypto') as typeof mod;
    } else if (typeof require === 'function') {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      mod = require('crypto');
    }
    if (mod && typeof mod.timingSafeEqual === 'function') nativeTimingSafeEqual = mod.timingSafeEqual;
  } catch {
    nativeTimingSafeEqual = null;
  }
  return nativeTimingSafeEqual;
}

/**
 * Constant-time XOR comparison used where Node's native implementation is
 * unavailable (browsers, edge runtimes). Lengths must already be equal.
 * @internal exported for tests only
 */
export function timingSafeEqualFallback(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Constant-time byte comparison to mitigate timing attacks.
 *
 * Returns false immediately when the lengths differ (length is not treated as
 * secret — MAC/signature lengths are public). For equal lengths it uses Node's
 * native `crypto.timingSafeEqual` when available, otherwise a constant-time
 * JS XOR loop.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  const native = getNativeTimingSafeEqual();
  if (native) return native(a, b);
  return timingSafeEqualFallback(a, b);
}

/** Concat multiple Uint8Arrays into one */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/**
 * Convert a hex string to Uint8Array.
 * Accepts upper- and lowercase digits. Throws a `CODEC_ERROR` on odd length
 * or any non-hex character (previously such characters silently became 0x00).
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new EncryptixError('CODEC_ERROR', `Hex input must be a string, got ${typeof hex}.`);
  }
  if (hex.length % 2 !== 0) {
    throw new EncryptixError('CODEC_ERROR', `Invalid hex string: length must be even, got ${hex.length}.`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const hi = hexNibble(hex.charCodeAt(i));
    const lo = hexNibble(hex.charCodeAt(i + 1));
    if (hi < 0 || lo < 0) {
      const pos = hi < 0 ? i : i + 1;
      throw new EncryptixError('CODEC_ERROR', `Invalid hex string: non-hex character at position ${pos}.`);
    }
    bytes[i / 2] = (hi << 4) | lo;
  }
  return bytes;
}

function hexNibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48; // 0-9
  if (c >= 97 && c <= 102) return c - 87; // a-f
  if (c >= 65 && c <= 70) return c - 55; // A-F
  return -1;
}

/** Convert a Uint8Array to lowercase hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Convert a Uint8Array to base64 string */
export function bytesToBase64(bytes: Uint8Array, urlSafe = false): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return urlSafe ? base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : base64;
}

/** Convert a base64 string to Uint8Array */
export function base64ToBytes(b64: string): Uint8Array {
  // Handle base64url
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

/** Encode bytes to the requested output format */
export function encodeOutput(bytes: Uint8Array, encoding: 'base64' | 'base64url' | 'hex'): string {
  if (encoding === 'hex') return bytesToHex(bytes);
  if (encoding === 'base64url') return bytesToBase64(bytes, true);
  return bytesToBase64(bytes, false);
}

/** Decode a string from the requested input format to bytes */
export function decodeInput(s: string, encoding: 'base64' | 'base64url' | 'hex'): Uint8Array {
  if (encoding === 'hex') return hexToBytes(s);
  return base64ToBytes(s); // handles both base64 and base64url
}
