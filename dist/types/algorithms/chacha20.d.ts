/**
 * ChaCha20-Poly1305 authenticated encryption.
 *
 * ChaCha20-Poly1305 is NOT available in the Web Crypto API (as of 2025),
 * so we use Node's native `crypto` module on Node runtimes.
 *
 * For browser/edge environments we throw a clear error; callers should
 * fall back to AES-256-GCM which is universally available.
 *
 * Payload binary layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x02 = chacha20-poly1305
 *   [12 bytes iv/nonce]
 *   [16 bytes tag    ]
 *   [N bytes ciphertext]
 */
import type { HashAlgorithm } from '../types/index.js';
export declare const ALGO_ID = 2;
export declare function chachaEncrypt(plaintext: string, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<Uint8Array>;
export declare function chachaDecrypt(data: Uint8Array, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<string>;
//# sourceMappingURL=chacha20.d.ts.map