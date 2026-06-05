/**
 * AES-SIV (Synthetic IV) — Deterministic Authenticated Encryption
 *
 * RFC 5297: https://tools.ietf.org/html/rfc5297
 *
 * AES-SIV encrypts the same plaintext to the same ciphertext given the same
 * key and AAD. This enables:
 *   - Searching over encrypted data (encrypted email lookup, encrypted index)
 *   - Deduplication of encrypted values
 *   - Deterministic token generation
 *
 * ⚠️ IMPORTANT SECURITY NOTES:
 *   1. Nonce-reuse resistant but NOT nonce-reuse immune — if you encrypt the
 *      same plaintext twice you get the same ciphertext, which leaks equality.
 *      This is by design and is the point. Only use when equality-leakage is acceptable.
 *   2. Do NOT use for data that requires hiding whether two values are equal.
 *      Use regular AES-GCM encrypt() for that.
 *   3. Binding AAD to the ciphertext is critical for domain separation.
 *      Always pass a meaningful `purpose` (which we do via HKDF).
 *
 * Implementation:
 *   AES-SIV uses two AES keys:
 *     K1 — for S2V (CMAC-based synthetic IV generation)
 *     K2 — for AES-CTR encryption
 *
 *   We implement CMAC via AES-CBC (available in Web Crypto):
 *     CMAC(K, M) = AES-CBC-MAC with subkey derivation per NIST SP 800-38B
 *
 * Layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x03 = aes-siv
 *   [16 bytes SIV/tag ]
 *   [N bytes ciphertext]
 */
import type { HashAlgorithm } from '../types/index.js';
export declare const ALGO_ID = 3;
export declare function sivEncrypt(plaintext: string, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<Uint8Array>;
export declare function sivDecrypt(data: Uint8Array, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<string>;
//# sourceMappingURL=aes-siv.d.ts.map