/**
 * Environment detection and cross-runtime crypto abstraction.
 * Supports Node.js ≥18, modern browsers (Web Crypto), and edge runtimes
 * (Cloudflare Workers, Vercel Edge, Deno) that expose the Web Crypto API.
 */
export type RuntimeEnv = 'node' | 'browser' | 'edge' | 'unknown';
export declare const RUNTIME: RuntimeEnv;
/**
 * Returns the platform's crypto object.
 * - Node.js:  `require('crypto').webcrypto` (available since Node 15, stable 18+)
 * - Browser:  `window.crypto`
 * - Edge:     `globalThis.crypto`
 */
export declare function getCrypto(): Crypto;
/**
 * Returns Node's native `crypto` module only when running in Node.
 * Used for algorithms not yet in Web Crypto (e.g. hkdfSync, createHash).
 */
export declare function getNodeCrypto(): Promise<typeof import('crypto') | null>;
/** Encode a string to Uint8Array via TextEncoder (available everywhere) */
export declare const encode: (s: string) => Uint8Array;
/** Decode a Uint8Array to string via TextDecoder */
export declare const decode: (b: Uint8Array) => string;
/** Constant-time comparison to mitigate timing attacks */
export declare function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
/** Concat multiple Uint8Arrays into one */
export declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
/** Convert a hex string to Uint8Array */
export declare function hexToBytes(hex: string): Uint8Array;
/** Convert a Uint8Array to lowercase hex string */
export declare function bytesToHex(bytes: Uint8Array): string;
/** Convert a Uint8Array to base64 string */
export declare function bytesToBase64(bytes: Uint8Array, urlSafe?: boolean): string;
/** Convert a base64 string to Uint8Array */
export declare function base64ToBytes(b64: string): Uint8Array;
/** Encode bytes to the requested output format */
export declare function encodeOutput(bytes: Uint8Array, encoding: 'base64' | 'base64url' | 'hex'): string;
/** Decode a string from the requested input format to bytes */
export declare function decodeInput(s: string, encoding: 'base64' | 'base64url' | 'hex'): Uint8Array;
//# sourceMappingURL=env.d.ts.map