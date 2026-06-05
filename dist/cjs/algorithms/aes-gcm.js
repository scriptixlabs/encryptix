"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.TAG_LENGTH = exports.IV_LENGTH = exports.ALGO_ID = void 0;
exports.aesEncrypt = aesEncrypt;
exports.aesDecrypt = aesDecrypt;
const env_js_1 = require("../utils/env.js");
const kdf_js_1 = require("../utils/kdf.js");
const errors_js_1 = require("../utils/errors.js");
exports.ALGO_ID = 0x01;
exports.IV_LENGTH = 12;
exports.TAG_LENGTH = 16;
const VERSION = 0x01;
async function aesEncrypt(plaintext, masterKeyHex, purpose, namespace, hash, aad) {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const key = await (0, kdf_js_1.deriveKey)(masterKeyHex, purpose, namespace, hash);
    const iv = (0, env_js_1.getCrypto)().getRandomValues(new Uint8Array(exports.IV_LENGTH));
    // Build AAD = purpose + optional extra aad
    const purposeBytes = (0, env_js_1.encode)(purpose);
    const effectiveAAD = aad ? (0, env_js_1.concatBytes)(purposeBytes, aad) : purposeBytes;
    let ciphertextWithTag;
    try {
        ciphertextWithTag = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: effectiveAAD, tagLength: exports.TAG_LENGTH * 8 }, key, (0, env_js_1.encode)(plaintext));
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ENCRYPTION_FAILED', 'AES-256-GCM encryption failed.', err);
    }
    // Web Crypto appends the auth tag at the END of the ciphertext buffer
    const full = new Uint8Array(ciphertextWithTag);
    const ciphertext = full.slice(0, full.length - exports.TAG_LENGTH);
    const tag = full.slice(full.length - exports.TAG_LENGTH);
    return (0, env_js_1.concatBytes)(new Uint8Array([VERSION, exports.ALGO_ID]), iv, tag, ciphertext);
}
async function aesDecrypt(data, masterKeyHex, purpose, namespace, hash, aad) {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const version = data[0];
    if (version !== VERSION) {
        throw new errors_js_1.EncryptixError('UNSUPPORTED_VERSION', `Unsupported payload version: ${version}`);
    }
    const algoId = data[1];
    if (algoId !== exports.ALGO_ID) {
        throw new errors_js_1.EncryptixError('UNSUPPORTED_ALGORITHM', `Payload algo_id ${algoId} is not AES-256-GCM (0x01)`);
    }
    const iv = data.slice(2, 2 + exports.IV_LENGTH);
    const tag = data.slice(2 + exports.IV_LENGTH, 2 + exports.IV_LENGTH + exports.TAG_LENGTH);
    const ciphertext = data.slice(2 + exports.IV_LENGTH + exports.TAG_LENGTH);
    const key = await (0, kdf_js_1.deriveKey)(masterKeyHex, purpose, namespace, hash);
    const purposeBytes = (0, env_js_1.encode)(purpose);
    const effectiveAAD = aad ? (0, env_js_1.concatBytes)(purposeBytes, aad) : purposeBytes;
    // Re-assemble ciphertext + tag for Web Crypto
    const ciphertextWithTag = (0, env_js_1.concatBytes)(ciphertext, tag);
    let plainBuffer;
    try {
        plainBuffer = await subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: effectiveAAD, tagLength: exports.TAG_LENGTH * 8 }, key, ciphertextWithTag);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('DECRYPTION_FAILED', 'AES-256-GCM decryption failed. The payload may be corrupt, tampered, or the wrong purpose/key was used.', err);
    }
    return new TextDecoder().decode(plainBuffer);
}
//# sourceMappingURL=aes-gcm.js.map