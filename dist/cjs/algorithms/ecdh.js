"use strict";
/**
 * ECDH Key Agreement + ECDSA Digital Signatures
 *
 * ECDH (Elliptic Curve Diffie-Hellman):
 *   Two parties each generate an EC key pair and derive the same shared
 *   secret without ever transmitting it. The shared secret is then fed
 *   into HKDF to produce a symmetric encryption key.
 *
 *   Use case: end-to-end encrypted messaging, forward secrecy, key exchange
 *   without a pre-shared key.
 *
 * ECDSA (Elliptic Curve Digital Signature Algorithm):
 *   Sign data with a private key; anyone with the public key can verify.
 *   Unlike HMAC, verification does not require the signing key.
 *
 *   Use case: document signing, webhook authenticity, audit logs, JWT-style
 *   tokens where the verifier is untrusted (e.g. a client).
 *
 * Both use NIST P-256 (secp256r1) by default — universally available via
 * Web Crypto, hardware-accelerated on most platforms.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateECDHKeyPair = generateECDHKeyPair;
exports.deriveSharedSecret = deriveSharedSecret;
exports.generateECDSAKeyPair = generateECDSAKeyPair;
exports.ecdsaSign = ecdsaSign;
exports.ecdsaVerify = ecdsaVerify;
const env_js_1 = require("../utils/env.js");
const errors_js_1 = require("../utils/errors.js");
// ─── ECDH ─────────────────────────────────────────────────────────────────────
/**
 * Generate an ECDH key pair for key agreement.
 * Returns PEM-encoded public/private keys plus raw JWK for storage.
 */
async function generateECDHKeyPair(curve = 'P-256') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    let keyPair;
    try {
        keyPair = await subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveKey', 'deriveBits']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDH_ERROR', `Failed to generate ECDH key pair for curve ${curve}.`, err);
    }
    const [spki, pkcs8] = await Promise.all([
        subtle.exportKey('spki', keyPair.publicKey),
        subtle.exportKey('pkcs8', keyPair.privateKey),
    ]);
    return {
        publicKey: toPEM(spki, 'PUBLIC KEY'),
        privateKey: toPEM(pkcs8, 'PRIVATE KEY'),
        curve,
    };
}
/**
 * Derive a shared secret from your private key and the other party's public key.
 * Returns a 32-byte (256-bit) hex string suitable for use as a master key.
 *
 * Both parties independently call this with swapped keys and get the same result.
 *
 * @example
 * // Alice:
 * const aliceKeys = await generateECDHKeyPair();
 * const sharedKey = await deriveSharedSecret(aliceKeys.privateKey, bobPublicKeyPEM);
 * const enc = new EncryptixClient({ key: sharedKey });
 *
 * // Bob (same result):
 * const bobKeys = await generateECDHKeyPair();
 * const sharedKey = await deriveSharedSecret(bobKeys.privateKey, alicePublicKeyPEM);
 */
async function deriveSharedSecret(privateKeyPEM, peerPublicKeyPEM, curve = 'P-256', outputLength = 32) {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    let privateKey;
    let publicKey;
    try {
        privateKey = await subtle.importKey('pkcs8', fromPEM(privateKeyPEM), { name: 'ECDH', namedCurve: curve }, false, ['deriveBits']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDH_ERROR', 'Failed to import ECDH private key. Ensure it is a valid PEM-encoded PKCS8 key.', err);
    }
    try {
        publicKey = await subtle.importKey('spki', fromPEM(peerPublicKeyPEM), { name: 'ECDH', namedCurve: curve }, false, []);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDH_ERROR', 'Failed to import peer ECDH public key. Ensure it is a valid PEM-encoded SPKI key.', err);
    }
    let bits;
    try {
        bits = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, outputLength * 8);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDH_ERROR', 'Failed to derive shared secret. Keys may be from different curves.', err);
    }
    return (0, env_js_1.bytesToHex)(new Uint8Array(bits));
}
// ─── ECDSA ────────────────────────────────────────────────────────────────────
/**
 * Generate an ECDSA key pair for signing and verification.
 */
async function generateECDSAKeyPair(curve = 'P-256') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    let keyPair;
    try {
        keyPair = await subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDSA_ERROR', `Failed to generate ECDSA key pair for curve ${curve}.`, err);
    }
    const [spki, pkcs8] = await Promise.all([
        subtle.exportKey('spki', keyPair.publicKey),
        subtle.exportKey('pkcs8', keyPair.privateKey),
    ]);
    return {
        publicKey: toPEM(spki, 'PUBLIC KEY'),
        privateKey: toPEM(pkcs8, 'PRIVATE KEY'),
        curve,
    };
}
/**
 * Sign data with an ECDSA private key.
 * Returns a DER-encoded signature as base64 (default) or hex.
 *
 * @param data       - The message to sign (string or bytes)
 * @param privateKeyPEM - PEM-encoded PKCS8 private key
 */
async function ecdsaSign(data, privateKeyPEM, curve = 'P-256', encoding = 'base64') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const hash = curveHash(curve);
    const dataBytes = typeof data === 'string' ? (0, env_js_1.encode)(data) : data;
    let privateKey;
    try {
        privateKey = await subtle.importKey('pkcs8', fromPEM(privateKeyPEM), { name: 'ECDSA', namedCurve: curve }, false, ['sign']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDSA_ERROR', 'Failed to import ECDSA private key.', err);
    }
    let signature;
    try {
        signature = await subtle.sign({ name: 'ECDSA', hash }, privateKey, dataBytes);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDSA_ERROR', 'ECDSA signing failed.', err);
    }
    const sigBytes = new Uint8Array(signature);
    if (encoding === 'hex')
        return (0, env_js_1.bytesToHex)(sigBytes);
    if (encoding === 'base64url')
        return (0, env_js_1.bytesToBase64)(sigBytes, true);
    return (0, env_js_1.bytesToBase64)(sigBytes, false);
}
/**
 * Verify an ECDSA signature.
 * Returns true if the signature is valid, false otherwise.
 * Never throws on invalid signatures — only on key import errors.
 */
async function ecdsaVerify(data, signature, publicKeyPEM, curve = 'P-256', encoding = 'base64') {
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const hash = curveHash(curve);
    const dataBytes = typeof data === 'string' ? (0, env_js_1.encode)(data) : data;
    let sigBytes;
    try {
        sigBytes = encoding === 'hex' ? (0, env_js_1.hexToBytes)(signature) : (0, env_js_1.base64ToBytes)(signature);
    }
    catch {
        return false;
    }
    let publicKey;
    try {
        publicKey = await subtle.importKey('spki', fromPEM(publicKeyPEM), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('ECDSA_ERROR', 'Failed to import ECDSA public key.', err);
    }
    try {
        return await subtle.verify({ name: 'ECDSA', hash }, publicKey, sigBytes, dataBytes);
    }
    catch {
        return false;
    }
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function curveHash(curve) {
    if (curve === 'P-384')
        return 'SHA-384';
    if (curve === 'P-521')
        return 'SHA-512';
    return 'SHA-256'; // P-256
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
//# sourceMappingURL=ecdh.js.map