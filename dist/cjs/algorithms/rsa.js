"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateRSAKeyPair = generateRSAKeyPair;
exports.rsaEncrypt = rsaEncrypt;
exports.rsaDecrypt = rsaDecrypt;
const env_js_1 = require("../utils/env.js");
const errors_js_1 = require("../utils/errors.js");
// ─── Key Generation ───────────────────────────────────────────────────────────
async function generateRSAKeyPair(modulusLength = 2048, hash = 'SHA-256') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    let keyPair;
    try {
        keyPair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash }, true, ['encrypt', 'decrypt']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('RSA_KEY_ERROR', 'Failed to generate RSA key pair.', err);
    }
    const [spki, pkcs8] = await Promise.all([
        subtle.exportKey('spki', keyPair.publicKey),
        subtle.exportKey('pkcs8', keyPair.privateKey),
    ]);
    return {
        publicKey: toPEM(spki, 'PUBLIC KEY'),
        privateKey: toPEM(pkcs8, 'PRIVATE KEY'),
    };
}
// ─── Encrypt ─────────────────────────────────────────────────────────────────
async function rsaEncrypt(plaintext, publicKeyPEM, encoding = 'base64', hash = 'SHA-256') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const publicKey = await importPublicKey(publicKeyPEM, hash);
    let ciphertext;
    try {
        ciphertext = await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, (0, env_js_1.encode)(plaintext));
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ENCRYPTION_FAILED', 'RSA-OAEP encryption failed.', err);
    }
    const bytes = new Uint8Array(ciphertext);
    if (encoding === 'hex')
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    if (encoding === 'base64url')
        return (0, env_js_1.bytesToBase64)(bytes, true);
    return (0, env_js_1.bytesToBase64)(bytes, false);
}
// ─── Decrypt ─────────────────────────────────────────────────────────────────
async function rsaDecrypt(ciphertext, privateKeyPEM, encoding = 'base64', hash = 'SHA-256') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const privateKey = await importPrivateKey(privateKeyPEM, hash);
    const ciphertextBytes = encoding === 'hex'
        ? Uint8Array.from(ciphertext.match(/.{1,2}/g).map(b => parseInt(b, 16)))
        : (0, env_js_1.base64ToBytes)(ciphertext);
    let plainBuffer;
    try {
        plainBuffer = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, ciphertextBytes);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('DECRYPTION_FAILED', 'RSA-OAEP decryption failed. Wrong key or corrupted ciphertext.', err);
    }
    return (0, env_js_1.decode)(new Uint8Array(plainBuffer));
}
// ─── Helpers ──────────────────────────────────────────────────────────────────
async function importPublicKey(pem, hash) {
    try {
        const spki = fromPEM(pem);
        return await (0, env_js_1.getCrypto)().subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash }, false, ['encrypt']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('RSA_KEY_ERROR', 'Failed to import RSA public key. Ensure it is a valid PEM-encoded SPKI key.', err);
    }
}
async function importPrivateKey(pem, hash) {
    try {
        const pkcs8 = fromPEM(pem);
        return await (0, env_js_1.getCrypto)().subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash }, false, ['decrypt']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('RSA_KEY_ERROR', 'Failed to import RSA private key. Ensure it is a valid PEM-encoded PKCS8 key.', err);
    }
}
function toPEM(buffer, label) {
    const base64 = (0, env_js_1.bytesToBase64)(new Uint8Array(buffer));
    const wrapped = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
function fromPEM(pem) {
    const base64 = pem
        .replace(/-----BEGIN [A-Z ]+-----/, '')
        .replace(/-----END [A-Z ]+-----/, '')
        .replace(/\s+/g, '');
    return (0, env_js_1.base64ToBytes)(base64).buffer;
}
//# sourceMappingURL=rsa.js.map