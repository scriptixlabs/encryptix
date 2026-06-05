/**
 * AES-256-GCM authenticated encryption using the Web Crypto API.
 * Works identically in Node 18+, browsers, and edge runtimes.
 *
 * Payload binary layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x01 = aes-256-gcm
 *   [12 bytes iv     ]
 *   [16 bytes tag    ]
 *   [N bytes ciphertext]
 */
import type { HashAlgorithm } from '../types/index.js';
export declare const ALGO_ID = 1;
export declare const IV_LENGTH = 12;
export declare const TAG_LENGTH = 16;
export declare function aesEncrypt(plaintext: string, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<Uint8Array>;
export declare function aesDecrypt(data: Uint8Array, masterKeyHex: string, purpose: string, namespace: string, hash: HashAlgorithm, aad?: Uint8Array): Promise<string>;
//# sourceMappingURL=aes-gcm.d.ts.map