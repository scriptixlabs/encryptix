"use strict";
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
exports.ALGO_ID = void 0;
exports.chachaEncrypt = chachaEncrypt;
exports.chachaDecrypt = chachaDecrypt;
const env_js_1 = require("../utils/env.js");
const kdf_js_1 = require("../utils/kdf.js");
const errors_js_1 = require("../utils/errors.js");
exports.ALGO_ID = 0x02;
const IV_LENGTH = 12; // ChaCha20 uses a 96-bit (12-byte) nonce
const TAG_LENGTH = 16;
const VERSION = 0x01;
function assertNodeRuntime() {
    if (env_js_1.RUNTIME !== 'node') {
        throw new errors_js_1.EncryptixError('ENVIRONMENT_UNSUPPORTED', 'ChaCha20-Poly1305 is only available in Node.js environments. ' +
            'Use aes-256-gcm for browser and edge runtime compatibility.');
    }
}
async function chachaEncrypt(plaintext, masterKeyHex, purpose, namespace, hash, aad) {
    assertNodeRuntime();
    const { createCipheriv, randomBytes } = await Promise.resolve().then(() => __importStar(require('crypto')));
    const rawKey = await (0, kdf_js_1.deriveRawKey)(masterKeyHex, purpose, namespace, hash);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv('chacha20-poly1305', rawKey, iv, {
        authTagLength: TAG_LENGTH,
    });
    const purposeBytes = (0, env_js_1.encode)(purpose);
    const effectiveAAD = aad ? (0, env_js_1.concatBytes)(purposeBytes, aad) : purposeBytes;
    cipher.setAAD(effectiveAAD, {});
    let encrypted;
    try {
        encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ENCRYPTION_FAILED', 'ChaCha20-Poly1305 encryption failed.', err);
    }
    const tag = cipher.getAuthTag();
    return (0, env_js_1.concatBytes)(new Uint8Array([VERSION, exports.ALGO_ID]), new Uint8Array(iv), new Uint8Array(tag), new Uint8Array(encrypted));
}
async function chachaDecrypt(data, masterKeyHex, purpose, namespace, hash, aad) {
    assertNodeRuntime();
    const version = data[0];
    if (version !== VERSION) {
        throw new errors_js_1.EncryptixError('UNSUPPORTED_VERSION', `Unsupported payload version: ${version}`);
    }
    const algoId = data[1];
    if (algoId !== exports.ALGO_ID) {
        throw new errors_js_1.EncryptixError('UNSUPPORTED_ALGORITHM', `Payload algo_id ${algoId} is not ChaCha20-Poly1305 (0x02)`);
    }
    const iv = data.slice(2, 2 + IV_LENGTH);
    const tag = data.slice(2 + IV_LENGTH, 2 + IV_LENGTH + TAG_LENGTH);
    const ciphertext = data.slice(2 + IV_LENGTH + TAG_LENGTH);
    const { createDecipheriv } = await Promise.resolve().then(() => __importStar(require('crypto')));
    const rawKey = await (0, kdf_js_1.deriveRawKey)(masterKeyHex, purpose, namespace, hash);
    const decipher = createDecipheriv('chacha20-poly1305', rawKey, iv, {
        authTagLength: TAG_LENGTH,
    });
    const purposeBytes = (0, env_js_1.encode)(purpose);
    const effectiveAAD = aad ? (0, env_js_1.concatBytes)(purposeBytes, aad) : purposeBytes;
    decipher.setAAD(effectiveAAD, {});
    decipher.setAuthTag(Buffer.from(tag));
    try {
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf8');
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('DECRYPTION_FAILED', 'ChaCha20-Poly1305 decryption failed. The payload may be corrupt, tampered, or the wrong purpose/key was used.', err);
    }
}
//# sourceMappingURL=chacha20.js.map