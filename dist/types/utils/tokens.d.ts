/**
 * Hashing, HMAC signing, and secure token generation utilities.
 * All functions use the Web Crypto API where possible for cross-runtime compatibility.
 */
import type { HashAlgorithm } from '../types/index.js';
/**
 * SHA-256 / SHA-384 / SHA-512 hash of a string or bytes.
 * Constant across all runtimes via Web Crypto.
 */
export declare function hash(input: string | Uint8Array, algorithm?: HashAlgorithm, encoding?: 'hex' | 'base64' | 'base64url'): Promise<string>;
/**
 * Produces an HMAC signature for a message using the given key.
 * Returns a hex string by default.
 */
export declare function hmac(message: string | Uint8Array, keyHex: string, algorithm?: HashAlgorithm, encoding?: 'hex' | 'base64' | 'base64url'): Promise<string>;
/**
 * Verifies an HMAC signature in constant time.
 * Returns true if valid, false otherwise.
 */
export declare function verifyHmac(message: string | Uint8Array, keyHex: string, signature: string, algorithm?: HashAlgorithm, encoding?: 'hex' | 'base64' | 'base64url'): Promise<boolean>;
/**
 * Generates a cryptographically random token.
 * @param bytes  - Number of random bytes (default: 32 → 64-char hex)
 * @param encoding - Output format
 */
export declare function generateToken(bytes?: number, encoding?: 'hex' | 'base64' | 'base64url'): string;
/**
 * Generates a secure random API key in the format `{prefix}_{base64url_random}`.
 * @example generateApiKey('sk') → 'sk_4xG9...'
 */
export declare function generateApiKey(prefix?: string, bytes?: number): string;
/**
 * Generates a UUID v4 using the platform's crypto.randomUUID if available,
 * falling back to manual construction.
 */
export declare function generateUUID(): string;
//# sourceMappingURL=tokens.d.ts.map