import type { HashAlgorithm } from '../types/index.js';
/**
 * Derives a cryptographic key from a master key using HKDF (RFC 5869).
 * Uses the Web Crypto API so it works in Node 18+, browsers, and edge runtimes.
 *
 * @param masterKeyHex - 64-char hex string (32-byte master key)
 * @param purpose      - Domain-separation string (e.g. 'user:session')
 * @param namespace    - Package namespace (default: 'encryptix')
 * @param hash         - Hash algorithm for HKDF (default: 'sha-256')
 * @param length       - Output key length in bytes (default: 32)
 * @param salt         - Optional salt bytes; defaults to zero-filled
 */
export declare function deriveKey(masterKeyHex: string, purpose: string, namespace?: string, hash?: HashAlgorithm, length?: number, salt?: Uint8Array): Promise<CryptoKey>;
/**
 * Derives raw key bytes (not a CryptoKey) for use with algorithms
 * that need the raw material (e.g. ChaCha20 via Node's native crypto).
 */
export declare function deriveRawKey(masterKeyHex: string, purpose: string, namespace?: string, hash?: HashAlgorithm, length?: number, salt?: Uint8Array): Promise<Uint8Array>;
//# sourceMappingURL=kdf.d.ts.map