/**
 * Encoding / Codec Utilities
 *
 * - Base32 encode/decode (RFC 4648) — needed for TOTP secrets and human-readable keys
 * - Constant-time base64 — timing-safe encode/decode
 * - safeCompare — constant-time comparison for tokens, MACs, signatures
 * - Encoding conversion helpers (hex ↔ base64 ↔ base64url ↔ bytes)
 */

import { EncryptixError } from './errors.js';

// ─── Base32 ───────────────────────────────────────────────────────────────────

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP = new Uint8Array(256).fill(0xff);
for (let i = 0; i < BASE32_CHARS.length; i++) {
  BASE32_LOOKUP[BASE32_CHARS.charCodeAt(i)] = i;
  // Support lowercase
  BASE32_LOOKUP[BASE32_CHARS.toLowerCase().charCodeAt(i)] = i;
}

/**
 * Encode bytes to a base32 string (RFC 4648, no padding).
 */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 0x1f];
  }
  return output;
}

/**
 * Decode a base32 string to bytes.
 * Accepts both upper and lowercase. Strips whitespace and padding.
 */
export function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const charCode = clean.charCodeAt(i);
    const idx = charCode < 256 ? BASE32_LOOKUP[charCode] : 0xff;
    if (idx === 0xff) {
      throw new EncryptixError('CODEC_ERROR', `Invalid base32 character at position ${i}: '${clean[i]}'`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

// ─── Hex ──────────────────────────────────────────────────────────────────────

/** Encode bytes to a lowercase hex string. */
export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Decode a hex string to bytes. */
export function hexDecode(hex: string): Uint8Array {
  const clean = hex.toLowerCase().trim();
  if (clean.length % 2 !== 0) {
    throw new EncryptixError('CODEC_ERROR', `Hex string must have even length, got ${clean.length}.`);
  }
  if (!/^[0-9a-f]*$/.test(clean)) {
    throw new EncryptixError('CODEC_ERROR', 'Hex string contains invalid characters.');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

// ─── Base64 ───────────────────────────────────────────────────────────────────

/** Encode bytes to base64. */
export function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** Encode bytes to base64url (URL-safe, no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Decode a base64 or base64url string to bytes. */
export function base64Decode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, '=');
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  } catch (err) {
    throw new EncryptixError('CODEC_ERROR', 'Invalid base64 string.', err);
  }
}

// ─── Encoding Conversion ─────────────────────────────────────────────────────

/**
 * Convert between encodings without going through string intermediates
 * more than necessary.
 *
 * @example
 * convertEncoding('aGVsbG8=', 'base64', 'hex')  // → '68656c6c6f'
 * convertEncoding('68656c6c6f', 'hex', 'base64url') // → 'aGVsbG8'
 */
export function convertEncoding(
  input: string,
  from: 'hex' | 'base64' | 'base64url',
  to: 'hex' | 'base64' | 'base64url',
): string {
  if (from === to) return input;

  let bytes: Uint8Array;
  if (from === 'hex') bytes = hexDecode(input);
  else bytes = base64Decode(input); // handles both base64 and base64url

  if (to === 'hex') return hexEncode(bytes);
  if (to === 'base64url') return base64urlEncode(bytes);
  return base64Encode(bytes);
}

// ─── Safe Compare ────────────────────────────────────────────────────────────

/**
 * Compare two strings or byte arrays in constant time.
 * Prevents timing attacks when comparing tokens, MACs, or signatures.
 *
 * Returns true only if both values are identical.
 * The comparison always takes O(n) time where n = max(a.length, b.length),
 * regardless of where the first difference occurs.
 *
 * @example
 * // Instead of:
 * if (userToken === storedToken)  // ❌ timing leak
 *
 * // Use:
 * if (safeCompare(userToken, storedToken))  // ✅ constant-time
 */
export function safeCompare(
  a: string | Uint8Array,
  b: string | Uint8Array,
): boolean {
  const enc = new TextEncoder();
  const ab = typeof a === 'string' ? enc.encode(a) : a;
  const bb = typeof b === 'string' ? enc.encode(b) : b;

  // Always compare max(len) bytes — pad the shorter one with zeros
  const len = Math.max(ab.length, bb.length);
  let diff = ab.length ^ bb.length; // length difference contributes to diff

  for (let i = 0; i < len; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }

  return diff === 0;
}

// ─── Text / Bytes Helpers ─────────────────────────────────────────────────────

/** Encode a UTF-8 string to bytes. */
export function textEncode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Decode bytes to a UTF-8 string. */
export function textDecode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
