/**
 * EncryptixClient — primary interface for @ppabari/encryptix
 */
import { aesEncrypt, aesDecrypt, ALGO_ID as AES_ALGO_ID } from './algorithms/aes-gcm.js';
import { chachaEncrypt, chachaDecrypt, ALGO_ID as CHACHA_ALGO_ID } from './algorithms/chacha20.js';
import { generateRSAKeyPair, rsaEncrypt, rsaDecrypt } from './algorithms/rsa.js';
import { generateRSAPSSKeyPair, rsaPssSign, rsaPssVerify } from './algorithms/rsa-sign.js';
import { generateECDHKeyPair, deriveSharedSecret, generateECDSAKeyPair, ecdsaSign, ecdsaVerify } from './algorithms/ecdh.js';
import { envelopeEncrypt, envelopeDecrypt } from './algorithms/envelope.js';
import { signToken, verifyToken } from './algorithms/signed-token.js';
import { sivEncrypt, sivDecrypt } from './algorithms/aes-siv.js';
import { createEncryptStream, createDecryptStream } from './algorithms/streaming.js';
import { deriveKeyFromPassword } from './algorithms/password.js';
import { generateTOTPSecret, generateTOTP, verifyTOTP, generateHOTP, totpKeyUri } from './algorithms/otp.js';
import { multiRecipientEncrypt, multiRecipientDecrypt, addRecipient, removeRecipient } from './algorithms/multi-recipient.js';
import { hash, hmac, verifyHmac, generateToken, generateApiKey, generateUUID } from './utils/tokens.js';
import { resolveMasterKey, resolveKeychainKey } from './utils/keys.js';
import { encodeOutput, decodeInput, encode } from './utils/env.js';
import { EncryptixError } from './utils/errors.js';
import { hash as hashFn } from './utils/tokens.js';
import { secureRandomBytes, secureRandomInt, secureRandomFloat, secureRandomString, secureRandomChoice, secureRandomSample, secureRandomShuffle } from './utils/random.js';
import { encryptBatch, decryptBatch, encryptBatchMixed, decryptBatchMixed, encryptBatchSafe, decryptBatchSafe } from './utils/batch.js';
import { inspectPayload, inspectStreamHeader, inspectToken } from './utils/inspect.js';
import { reEncrypt, serializeKey } from './utils/zeroize.js';
// ─── Re-exports ───────────────────────────────────────────────────────────────
export { EncryptixError } from './utils/errors.js';
export { generateMasterKey } from './utils/keys.js';
export { generateToken, generateApiKey, generateUUID, hash, hmac, verifyHmac } from './utils/tokens.js';
export { generateRSAKeyPair } from './algorithms/rsa.js';
export { generateRSAPSSKeyPair, rsaPssSign, rsaPssVerify } from './algorithms/rsa-sign.js';
export { generateECDHKeyPair, deriveSharedSecret, generateECDSAKeyPair, ecdsaSign, ecdsaVerify } from './algorithms/ecdh.js';
export { deriveKeyFromPassword } from './algorithms/password.js';
export { generateTOTPSecret, generateTOTP, verifyTOTP, generateHOTP, totpKeyUri, toBase32, fromBase32 } from './algorithms/otp.js';
export { multiRecipientEncrypt, multiRecipientDecrypt, addRecipient, removeRecipient } from './algorithms/multi-recipient.js';
export { secureRandomBytes, secureRandomInt, secureRandomFloat, secureRandomString, secureRandomChoice, secureRandomSample, secureRandomShuffle, securePassphrase, CHARSETS } from './utils/random.js';
export { encryptBatch, decryptBatch, encryptBatchMixed, decryptBatchMixed, encryptBatchSafe, decryptBatchSafe } from './utils/batch.js';
export { base32Encode, base32Decode, hexEncode, hexDecode, base64Encode, base64urlEncode, base64Decode, safeCompare, convertEncoding } from './utils/codec.js';
export { inspectPayload, inspectStreamHeader, inspectToken } from './utils/inspect.js';
export { zeroize, zeroizeAll, withZeroize, createKeyMetadataStore, reEncrypt, reEncryptBatch, exportKeyToJWK, importKeyFromJWK, serializeKey, deserializeKey } from './utils/zeroize.js';
const HEADER_SIZE = 4;
function buildTTLAad(ttlSeconds, extraAad) {
    if (ttlSeconds === undefined && extraAad === undefined)
        return undefined;
    const parts = [];
    if (ttlSeconds !== undefined) {
        const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
        const expiryBytes = new Uint8Array(8);
        new DataView(expiryBytes.buffer).setUint32(0, Math.floor(expiry / 0x100000000), false);
        new DataView(expiryBytes.buffer).setUint32(4, expiry >>> 0, false);
        parts.push(encode('ttl:'), expiryBytes);
    }
    if (extraAad)
        parts.push(extraAad);
    const total = parts.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}
export class EncryptixClient {
    constructor(config = {}) {
        this.masterKey = resolveMasterKey(config.key);
        this.algorithm = config.algorithm ?? 'aes-256-gcm';
        this.encoding = config.encoding ?? 'base64';
        this.hashAlgorithm = config.hashAlgorithm ?? 'sha256';
        this.namespace = config.namespace ?? 'encryptix';
        this.keychain = config.keychain ?? {};
        const versions = Object.keys(this.keychain).map(Number);
        this.currentKeyVersion = versions.length > 0 ? Math.max(...versions) + 1 : 1;
    }
    // ─── Symmetric ──────────────────────────────────────────────────────────────
    async encrypt(plaintext, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const algo = options.algorithm ?? this.algorithm;
        const encoding = options.encoding ?? this.encoding;
        const extraAad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
        const aad = buildTTLAad(options.ttlSeconds, extraAad);
        let payload;
        if (algo === 'aes-256-gcm') {
            payload = await aesEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        }
        else if (algo === 'chacha20-poly1305') {
            payload = await chachaEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        }
        else {
            throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algorithm: ${algo}`);
        }
        const kv = new Uint8Array(2);
        new DataView(kv.buffer).setUint16(0, this.currentKeyVersion, false);
        const out = new Uint8Array(2 + payload.length);
        out.set(payload.slice(0, 2));
        out.set(kv, 2);
        out.set(payload.slice(2), 4);
        return encodeOutput(out, encoding);
    }
    async decrypt(payload, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const encoding = options.encoding ?? this.encoding;
        const extraAad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
        let data;
        try {
            data = decodeInput(payload, encoding);
        }
        catch (err) {
            throw new EncryptixError('INVALID_PAYLOAD', 'Failed to decode payload.', err);
        }
        if (data.length < HEADER_SIZE + 12 + 16)
            throw new EncryptixError('INVALID_PAYLOAD', 'Payload is too short.');
        const algoId = data[1];
        const keyVersion = new DataView(data.buffer, data.byteOffset + 2, 2).getUint16(0, false);
        const stripped = new Uint8Array(data.length - 2);
        stripped.set(data.slice(0, 2));
        stripped.set(data.slice(4), 2);
        const key = this.resolveDecryptionKey(keyVersion);
        if (algoId === AES_ALGO_ID)
            return aesDecrypt(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
        if (algoId === CHACHA_ALGO_ID)
            return chachaDecrypt(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
        throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algo_id: 0x${algoId.toString(16)}`);
    }
    // ─── Object ─────────────────────────────────────────────────────────────────
    async encryptObject(value, purpose, options = {}) {
        const serialize = options.serialize ?? JSON.stringify;
        const wrapper = { d: value, ...(options.ttlSeconds !== undefined ? { exp: Math.floor(Date.now() / 1000) + options.ttlSeconds } : {}) };
        let serialized;
        try {
            serialized = serialize(wrapper);
        }
        catch (err) {
            throw new EncryptixError('ENCRYPTION_FAILED', 'Failed to serialize object.', err);
        }
        return this.encrypt(serialized, purpose, { algorithm: options.algorithm, encoding: options.encoding, aad: options.aad });
    }
    async decryptObject(payload, purpose, options = {}) {
        const raw = await this.decrypt(payload, purpose, options);
        const deserialize = options.deserialize ?? JSON.parse;
        let wrapper;
        try {
            wrapper = deserialize(raw);
        }
        catch (err) {
            throw new EncryptixError('INVALID_PAYLOAD', 'Failed to deserialize decrypted object.', err);
        }
        if (wrapper.exp !== undefined && Math.floor(Date.now() / 1000) > wrapper.exp) {
            throw new EncryptixError('PAYLOAD_EXPIRED', `Payload expired ${Math.floor(Date.now() / 1000) - wrapper.exp}s ago.`);
        }
        return wrapper.d;
    }
    // ─── Batch ──────────────────────────────────────────────────────────────────
    async encryptBatch(items, purpose, options) {
        return encryptBatch(this.encrypt.bind(this), items, purpose, options);
    }
    async decryptBatch(payloads, purpose, options) {
        return decryptBatch(this.decrypt.bind(this), payloads, purpose, options);
    }
    async encryptBatchMixed(items) {
        return encryptBatchMixed(this.encrypt.bind(this), items);
    }
    async decryptBatchMixed(items) {
        return decryptBatchMixed(this.decrypt.bind(this), items);
    }
    async encryptBatchSafe(items, purpose, options) {
        return encryptBatchSafe(this.encrypt.bind(this), items, purpose, options);
    }
    async decryptBatchSafe(payloads, purpose, options) {
        return decryptBatchSafe(this.decrypt.bind(this), payloads, purpose, options);
    }
    // ─── Deterministic (AES-SIV) ─────────────────────────────────────────────
    async encryptDeterministic(plaintext, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
        const payload = await sivEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        return encodeOutput(payload, options.encoding ?? this.encoding);
    }
    async decryptDeterministic(payload, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
        let data;
        try {
            data = decodeInput(payload, options.encoding ?? this.encoding);
        }
        catch (err) {
            throw new EncryptixError('INVALID_PAYLOAD', 'Failed to decode deterministic payload.', err);
        }
        return sivDecrypt(data, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
    }
    // ─── Envelope ────────────────────────────────────────────────────────────
    async envelopeEncrypt(plaintext, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return envelopeEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
    }
    async envelopeDecrypt(envelope, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return envelopeDecrypt(envelope, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
    }
    // ─── Multi-Recipient ─────────────────────────────────────────────────────
    async multiRecipientEncrypt(plaintext, recipients, options = {}) {
        return multiRecipientEncrypt(plaintext, recipients, this.namespace, this.hashAlgorithm, options);
    }
    async multiRecipientDecrypt(envelope, recipientId, privateKeyPEM, options = {}) {
        return multiRecipientDecrypt(envelope, recipientId, privateKeyPEM, this.namespace, this.hashAlgorithm, options);
    }
    addRecipient(envelope, existingId, existingPrivateKeyPEM, newRecipient) {
        return addRecipient(envelope, existingId, existingPrivateKeyPEM, newRecipient);
    }
    removeRecipient(envelope, recipientId) {
        return removeRecipient(envelope, recipientId);
    }
    // ─── Signed Tokens ────────────────────────────────────────────────────────
    async sign(payload, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return signToken(payload, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    async verify(token, purpose, options = {}) {
        if (!purpose)
            throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return verifyToken(token, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    // ─── Streaming ───────────────────────────────────────────────────────────
    encryptStream(options) {
        return createEncryptStream(this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    decryptStream(options) {
        return createDecryptStream(this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    // ─── RSA ─────────────────────────────────────────────────────────────────
    async generateRSAKeyPair(modulusLength = 2048) { return generateRSAKeyPair(modulusLength); }
    async encryptRSA(plaintext, publicKeyPEM, encoding = this.encoding) { return rsaEncrypt(plaintext, publicKeyPEM, encoding); }
    async decryptRSA(ciphertext, privateKeyPEM, encoding = this.encoding) { return rsaDecrypt(ciphertext, privateKeyPEM, encoding); }
    async generateRSAPSSKeyPair(modulusLength = 2048) { return generateRSAPSSKeyPair(modulusLength); }
    async signRSA(data, privateKeyPEM, encoding = this.encoding) { return rsaPssSign(data, privateKeyPEM, 'SHA-256', encoding); }
    async verifyRSA(data, signature, publicKeyPEM, encoding = this.encoding) { return rsaPssVerify(data, signature, publicKeyPEM, 'SHA-256', encoding); }
    // ─── ECDH / ECDSA ────────────────────────────────────────────────────────
    async generateECDHKeyPair(curve = 'P-256') { return generateECDHKeyPair(curve); }
    async deriveSharedSecret(privateKeyPEM, peerPublicKeyPEM, curve = 'P-256') { return deriveSharedSecret(privateKeyPEM, peerPublicKeyPEM, curve); }
    async generateECDSAKeyPair(curve = 'P-256') { return generateECDSAKeyPair(curve); }
    async signECDSA(data, privateKeyPEM, curve = 'P-256', encoding = this.encoding) { return ecdsaSign(data, privateKeyPEM, curve, encoding); }
    async verifyECDSA(data, signature, publicKeyPEM, curve = 'P-256', encoding = this.encoding) { return ecdsaVerify(data, signature, publicKeyPEM, curve, encoding); }
    // ─── TOTP / HOTP ────────────────────────────────────────────────────────
    generateTOTPSecret(bytes = 20) { return generateTOTPSecret(bytes); }
    totpKeyUri(secret, account, issuer, options) { return totpKeyUri(secret, account, issuer, options); }
    async generateTOTP(secret, options) { return generateTOTP(secret, options); }
    async generateHOTP(secret, counter, options) { return generateHOTP(secret, counter, options); }
    async verifyTOTP(code, secret, options) { return verifyTOTP(code, secret, options); }
    // ─── Password KDF ────────────────────────────────────────────────────────
    async deriveKeyFromPassword(password, purpose, options = {}) { return deriveKeyFromPassword(password, purpose, options); }
    // ─── Hashing / HMAC ──────────────────────────────────────────────────────
    async hash(input, algorithm = this.hashAlgorithm, encoding = 'hex') { return hash(input, algorithm, encoding); }
    async hmac(message, keyHex = this.masterKey, algorithm = this.hashAlgorithm, encoding = 'hex') { return hmac(message, keyHex, algorithm, encoding); }
    async verifyHmac(message, signature, keyHex = this.masterKey, algorithm = this.hashAlgorithm, encoding = 'hex') { return verifyHmac(message, keyHex, signature, algorithm, encoding); }
    // ─── Inspect ────────────────────────────────────────────────────────────
    inspectPayload(payload, encoding) { return inspectPayload(payload, encoding ?? this.encoding); }
    inspectStreamHeader(headerBytes) { return inspectStreamHeader(headerBytes); }
    inspectToken(token) { return inspectToken(token); }
    // ─── Key Operations ───────────────────────────────────────────────────────
    async keyFingerprint() {
        const digest = await hashFn(new TextEncoder().encode(this.masterKey), 'sha256', 'hex');
        return { fingerprint: digest.slice(0, 16), version: this.currentKeyVersion };
    }
    rotate(newMasterKeyHex) {
        return new EncryptixClient({
            key: newMasterKeyHex, algorithm: this.algorithm, encoding: this.encoding,
            hashAlgorithm: this.hashAlgorithm, namespace: this.namespace,
            keychain: { ...this.keychain, [this.currentKeyVersion]: this.masterKey },
        });
    }
    async reEncrypt(payload, fromPurpose, toPurpose, options) {
        return reEncrypt(payload, { decryptFn: this.decrypt.bind(this), purpose: fromPurpose, options: options?.fromOptions }, { encryptFn: this.encrypt.bind(this), purpose: toPurpose, options: options?.toOptions });
    }
    async exportKey(format = 'hex') { return serializeKey(this.masterKey, format); }
    // ─── Token / ID Generation ───────────────────────────────────────────────
    generateToken(bytes = 32, encoding = 'hex') { return generateToken(bytes, encoding); }
    generateApiKey(prefix = 'key', bytes = 32) { return generateApiKey(prefix, bytes); }
    generateUUID() { return generateUUID(); }
    // ─── Secure Random ────────────────────────────────────────────────────────
    randomBytes(n) { return secureRandomBytes(n); }
    randomInt(min, max) { return secureRandomInt(min, max); }
    randomFloat() { return secureRandomFloat(); }
    randomString(length, charset) { return secureRandomString(length, charset); }
    randomChoice(array) { return secureRandomChoice(array); }
    randomSample(array, n) { return secureRandomSample(array, n); }
    randomShuffle(array) { return secureRandomShuffle(array); }
    // ─── Private ─────────────────────────────────────────────────────────────
    resolveDecryptionKey(keyVersion) {
        if (keyVersion === 1 && Object.keys(this.keychain).length === 0)
            return this.masterKey;
        if (keyVersion === this.currentKeyVersion)
            return this.masterKey;
        return resolveKeychainKey(this.keychain, keyVersion);
    }
}
export function createEncryptix(config = {}) {
    return new EncryptixClient(config);
}
//# sourceMappingURL=client.js.map