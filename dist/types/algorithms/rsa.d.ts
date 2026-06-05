/**
 * RSA-OAEP asymmetric encryption using the Web Crypto API.
 * Works in Node 18+, modern browsers, and edge runtimes.
 *
 * Key size: 2048 or 4096 bits
 * Hash:     SHA-256 (default) or SHA-512
 *
 * Intended use: encrypt small payloads (e.g. symmetric keys, tokens).
 * For large data, encrypt with AES/ChaCha and use RSA to wrap the key.
 */
import type { RSAKeyPair, Encoding } from '../types/index.js';
type RSAHashAlg = 'SHA-256' | 'SHA-512';
export declare function generateRSAKeyPair(modulusLength?: 2048 | 4096, hash?: RSAHashAlg): Promise<RSAKeyPair>;
export declare function rsaEncrypt(plaintext: string, publicKeyPEM: string, encoding?: Encoding, hash?: RSAHashAlg): Promise<string>;
export declare function rsaDecrypt(ciphertext: string, privateKeyPEM: string, encoding?: Encoding, hash?: RSAHashAlg): Promise<string>;
export {};
//# sourceMappingURL=rsa.d.ts.map