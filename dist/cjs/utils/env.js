"use strict";
/**
 * Environment detection and cross-runtime crypto abstraction.
 * Supports Node.js ≥18, modern browsers (Web Crypto), and edge runtimes
 * (Cloudflare Workers, Vercel Edge, Deno) that expose the Web Crypto API.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.encode = exports.RUNTIME = void 0;
exports.getCrypto = getCrypto;
exports.getNodeCrypto = getNodeCrypto;
exports.timingSafeEqual = timingSafeEqual;
exports.concatBytes = concatBytes;
exports.hexToBytes = hexToBytes;
exports.bytesToHex = bytesToHex;
exports.bytesToBase64 = bytesToBase64;
exports.base64ToBytes = base64ToBytes;
exports.encodeOutput = encodeOutput;
exports.decodeInput = decodeInput;
function detectRuntime() {
    // Node.js
    if (typeof process !== 'undefined' && process.versions?.node)
        return 'node';
    // Browser
    if (typeof window !== 'undefined' && typeof window.crypto !== 'undefined')
        return 'browser';
    // Edge (Cloudflare Workers, Deno, etc.)
    if (typeof globalThis !== 'undefined' && typeof globalThis.crypto !== 'undefined')
        return 'edge';
    return 'unknown';
}
exports.RUNTIME = detectRuntime();
/**
 * Returns the platform's crypto object.
 * - Node.js:  `require('crypto').webcrypto` (available since Node 15, stable 18+)
 * - Browser:  `window.crypto`
 * - Edge:     `globalThis.crypto`
 */
function getCrypto() {
    if (exports.RUNTIME === 'node') {
        // Node 18+ has globalThis.crypto
        if (typeof globalThis.crypto !== 'undefined')
            return globalThis.crypto;
        // Fallback for older Node builds
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const nodeCrypto = require('crypto');
        return nodeCrypto.webcrypto;
    }
    if (typeof globalThis.crypto !== 'undefined')
        return globalThis.crypto;
    if (typeof window !== 'undefined' && window.crypto)
        return window.crypto;
    throw new Error('No crypto implementation found in this environment.');
}
/**
 * Returns Node's native `crypto` module only when running in Node.
 * Used for algorithms not yet in Web Crypto (e.g. hkdfSync, createHash).
 */
async function getNodeCrypto() {
    if (exports.RUNTIME !== 'node')
        return null;
    try {
        // Dynamic import works in both ESM and CJS via the interop
        const mod = await Promise.resolve().then(() => __importStar(require('crypto')));
        return mod.default ?? mod;
    }
    catch {
        return null;
    }
}
/** Encode a string to Uint8Array via TextEncoder (available everywhere) */
const encode = (s) => new TextEncoder().encode(s);
exports.encode = encode;
/** Decode a Uint8Array to string via TextDecoder */
const decode = (b) => new TextDecoder().decode(b);
exports.decode = decode;
/** Constant-time comparison to mitigate timing attacks */
function timingSafeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
/** Concat multiple Uint8Arrays into one */
function concatBytes(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const arr of arrays) {
        out.set(arr, offset);
        offset += arr.length;
    }
    return out;
}
/** Convert a hex string to Uint8Array */
function hexToBytes(hex) {
    if (hex.length % 2 !== 0)
        throw new Error(`Invalid hex string length: ${hex.length}`);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}
/** Convert a Uint8Array to lowercase hex string */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
/** Convert a Uint8Array to base64 string */
function bytesToBase64(bytes, urlSafe = false) {
    const base64 = btoa(String.fromCharCode(...bytes));
    return urlSafe ? base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : base64;
}
/** Convert a base64 string to Uint8Array */
function base64ToBytes(b64) {
    // Handle base64url
    const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}
/** Encode bytes to the requested output format */
function encodeOutput(bytes, encoding) {
    if (encoding === 'hex')
        return bytesToHex(bytes);
    if (encoding === 'base64url')
        return bytesToBase64(bytes, true);
    return bytesToBase64(bytes, false);
}
/** Decode a string from the requested input format to bytes */
function decodeInput(s, encoding) {
    if (encoding === 'hex')
        return hexToBytes(s);
    return base64ToBytes(s); // handles both base64 and base64url
}
//# sourceMappingURL=env.js.map