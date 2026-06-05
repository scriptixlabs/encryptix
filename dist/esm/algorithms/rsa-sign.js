/**
 * RSA-PSS Digital Signatures
 *
 * RSA-PSS (Probabilistic Signature Scheme) is the modern RSA signing standard.
 * It is intentionally separate from RSA-OAEP (encryption) — the same key pair
 * should NOT be used for both signing and encryption.
 *
 * Use ECDSA for new code when possible — RSA-PSS is here for interoperability
 * with systems that require RSA signatures (older APIs, FIPS environments, etc).
 *
 * Why RSA-PSS over PKCS1v1.5?
 *   - PSS has a formal security proof; PKCS1v1.5 does not.
 *   - PSS is randomized (different signature each time); PKCS1v1.5 is deterministic.
 *   - PKCS1v1.5 is vulnerable to certain padding oracle attacks.
 */
import { getCrypto, encode, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes } from '../utils/env.js';
import { EncryptixError } from '../utils/errors.js';
// ─── Key Generation ───────────────────────────────────────────────────────────
/**
 * Generate an RSA-PSS key pair for signing.
 * Use a separate key pair from your RSA-OAEP encryption keys.
 */
export async function generateRSAPSSKeyPair(modulusLength = 2048, hash = 'SHA-256') {
    const subtle = getCrypto().subtle;
    let keyPair;
    try {
        keyPair = await subtle.generateKey({
            name: 'RSA-PSS',
            modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash,
        }, true, ['sign', 'verify']);
    }
    catch (err) {
        throw new EncryptixError('RSA_SIGN_ERROR', 'Failed to generate RSA-PSS key pair.', err);
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
// ─── Sign ─────────────────────────────────────────────────────────────────────
/**
 * Sign data with an RSA-PSS private key.
 * Returns the signature as base64 (default), base64url, or hex.
 */
export async function rsaPssSign(data, privateKeyPEM, hash = 'SHA-256', encoding = 'base64') {
    const subtle = getCrypto().subtle;
    const saltLength = hash === 'SHA-512' ? 64 : hash === 'SHA-384' ? 48 : 32;
    const dataBytes = typeof data === 'string' ? encode(data) : data;
    let privateKey;
    try {
        privateKey = await subtle.importKey('pkcs8', fromPEM(privateKeyPEM), { name: 'RSA-PSS', hash }, false, ['sign']);
    }
    catch (err) {
        throw new EncryptixError('RSA_SIGN_ERROR', 'Failed to import RSA-PSS private key.', err);
    }
    let signature;
    try {
        signature = await subtle.sign({ name: 'RSA-PSS', saltLength }, privateKey, dataBytes);
    }
    catch (err) {
        throw new EncryptixError('RSA_SIGN_ERROR', 'RSA-PSS signing failed.', err);
    }
    const bytes = new Uint8Array(signature);
    if (encoding === 'hex')
        return bytesToHex(bytes);
    if (encoding === 'base64url')
        return bytesToBase64(bytes, true);
    return bytesToBase64(bytes, false);
}
// ─── Verify ──────────────────────────────────────────────────────────────────
/**
 * Verify an RSA-PSS signature.
 * Returns true if valid, false otherwise. Never throws on invalid signatures.
 */
export async function rsaPssVerify(data, signature, publicKeyPEM, hash = 'SHA-256', encoding = 'base64') {
    const subtle = getCrypto().subtle;
    const saltLength = hash === 'SHA-512' ? 64 : hash === 'SHA-384' ? 48 : 32;
    const dataBytes = typeof data === 'string' ? encode(data) : data;
    let sigBytes;
    try {
        sigBytes = encoding === 'hex' ? hexToBytes(signature) : base64ToBytes(signature);
    }
    catch {
        return false;
    }
    let publicKey;
    try {
        publicKey = await subtle.importKey('spki', fromPEM(publicKeyPEM), { name: 'RSA-PSS', hash }, false, ['verify']);
    }
    catch (err) {
        throw new EncryptixError('RSA_SIGN_ERROR', 'Failed to import RSA-PSS public key.', err);
    }
    try {
        return await subtle.verify({ name: 'RSA-PSS', saltLength }, publicKey, sigBytes, dataBytes);
    }
    catch {
        return false;
    }
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function toPEM(buffer, label) {
    const base64 = bytesToBase64(new Uint8Array(buffer));
    const wrapped = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
function fromPEM(pem) {
    const base64 = pem
        .replace(/-----BEGIN [A-Z ]+-----/, '')
        .replace(/-----END [A-Z ]+-----/, '')
        .replace(/\s+/g, '');
    return base64ToBytes(base64).buffer;
}
//# sourceMappingURL=rsa-sign.js.map