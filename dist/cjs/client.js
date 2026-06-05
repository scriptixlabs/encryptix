"use strict";
/**
 * EncryptixClient — primary interface for @ppabari/encryptix
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64urlEncode = exports.base64Encode = exports.hexDecode = exports.hexEncode = exports.base32Decode = exports.base32Encode = exports.decryptBatchSafe = exports.encryptBatchSafe = exports.decryptBatchMixed = exports.encryptBatchMixed = exports.decryptBatch = exports.encryptBatch = exports.CHARSETS = exports.securePassphrase = exports.secureRandomShuffle = exports.secureRandomSample = exports.secureRandomChoice = exports.secureRandomString = exports.secureRandomFloat = exports.secureRandomInt = exports.secureRandomBytes = exports.removeRecipient = exports.addRecipient = exports.multiRecipientDecrypt = exports.multiRecipientEncrypt = exports.fromBase32 = exports.toBase32 = exports.totpKeyUri = exports.generateHOTP = exports.verifyTOTP = exports.generateTOTP = exports.generateTOTPSecret = exports.deriveKeyFromPassword = exports.ecdsaVerify = exports.ecdsaSign = exports.generateECDSAKeyPair = exports.deriveSharedSecret = exports.generateECDHKeyPair = exports.rsaPssVerify = exports.rsaPssSign = exports.generateRSAPSSKeyPair = exports.generateRSAKeyPair = exports.verifyHmac = exports.hmac = exports.hash = exports.generateUUID = exports.generateApiKey = exports.generateToken = exports.generateMasterKey = exports.EncryptixError = void 0;
exports.EncryptixClient = exports.deserializeKey = exports.serializeKey = exports.importKeyFromJWK = exports.exportKeyToJWK = exports.reEncryptBatch = exports.reEncrypt = exports.createKeyMetadataStore = exports.withZeroize = exports.zeroizeAll = exports.zeroize = exports.inspectToken = exports.inspectStreamHeader = exports.inspectPayload = exports.convertEncoding = exports.safeCompare = exports.base64Decode = void 0;
exports.createEncryptix = createEncryptix;
const aes_gcm_js_1 = require("./algorithms/aes-gcm.js");
const chacha20_js_1 = require("./algorithms/chacha20.js");
const rsa_js_1 = require("./algorithms/rsa.js");
const rsa_sign_js_1 = require("./algorithms/rsa-sign.js");
const ecdh_js_1 = require("./algorithms/ecdh.js");
const envelope_js_1 = require("./algorithms/envelope.js");
const signed_token_js_1 = require("./algorithms/signed-token.js");
const aes_siv_js_1 = require("./algorithms/aes-siv.js");
const streaming_js_1 = require("./algorithms/streaming.js");
const password_js_1 = require("./algorithms/password.js");
const otp_js_1 = require("./algorithms/otp.js");
const multi_recipient_js_1 = require("./algorithms/multi-recipient.js");
const tokens_js_1 = require("./utils/tokens.js");
const keys_js_1 = require("./utils/keys.js");
const env_js_1 = require("./utils/env.js");
const errors_js_1 = require("./utils/errors.js");
const tokens_js_2 = require("./utils/tokens.js");
const random_js_1 = require("./utils/random.js");
const batch_js_1 = require("./utils/batch.js");
const inspect_js_1 = require("./utils/inspect.js");
const zeroize_js_1 = require("./utils/zeroize.js");
// ─── Re-exports ───────────────────────────────────────────────────────────────
var errors_js_2 = require("./utils/errors.js");
Object.defineProperty(exports, "EncryptixError", { enumerable: true, get: function () { return errors_js_2.EncryptixError; } });
var keys_js_2 = require("./utils/keys.js");
Object.defineProperty(exports, "generateMasterKey", { enumerable: true, get: function () { return keys_js_2.generateMasterKey; } });
var tokens_js_3 = require("./utils/tokens.js");
Object.defineProperty(exports, "generateToken", { enumerable: true, get: function () { return tokens_js_3.generateToken; } });
Object.defineProperty(exports, "generateApiKey", { enumerable: true, get: function () { return tokens_js_3.generateApiKey; } });
Object.defineProperty(exports, "generateUUID", { enumerable: true, get: function () { return tokens_js_3.generateUUID; } });
Object.defineProperty(exports, "hash", { enumerable: true, get: function () { return tokens_js_3.hash; } });
Object.defineProperty(exports, "hmac", { enumerable: true, get: function () { return tokens_js_3.hmac; } });
Object.defineProperty(exports, "verifyHmac", { enumerable: true, get: function () { return tokens_js_3.verifyHmac; } });
var rsa_js_2 = require("./algorithms/rsa.js");
Object.defineProperty(exports, "generateRSAKeyPair", { enumerable: true, get: function () { return rsa_js_2.generateRSAKeyPair; } });
var rsa_sign_js_2 = require("./algorithms/rsa-sign.js");
Object.defineProperty(exports, "generateRSAPSSKeyPair", { enumerable: true, get: function () { return rsa_sign_js_2.generateRSAPSSKeyPair; } });
Object.defineProperty(exports, "rsaPssSign", { enumerable: true, get: function () { return rsa_sign_js_2.rsaPssSign; } });
Object.defineProperty(exports, "rsaPssVerify", { enumerable: true, get: function () { return rsa_sign_js_2.rsaPssVerify; } });
var ecdh_js_2 = require("./algorithms/ecdh.js");
Object.defineProperty(exports, "generateECDHKeyPair", { enumerable: true, get: function () { return ecdh_js_2.generateECDHKeyPair; } });
Object.defineProperty(exports, "deriveSharedSecret", { enumerable: true, get: function () { return ecdh_js_2.deriveSharedSecret; } });
Object.defineProperty(exports, "generateECDSAKeyPair", { enumerable: true, get: function () { return ecdh_js_2.generateECDSAKeyPair; } });
Object.defineProperty(exports, "ecdsaSign", { enumerable: true, get: function () { return ecdh_js_2.ecdsaSign; } });
Object.defineProperty(exports, "ecdsaVerify", { enumerable: true, get: function () { return ecdh_js_2.ecdsaVerify; } });
var password_js_2 = require("./algorithms/password.js");
Object.defineProperty(exports, "deriveKeyFromPassword", { enumerable: true, get: function () { return password_js_2.deriveKeyFromPassword; } });
var otp_js_2 = require("./algorithms/otp.js");
Object.defineProperty(exports, "generateTOTPSecret", { enumerable: true, get: function () { return otp_js_2.generateTOTPSecret; } });
Object.defineProperty(exports, "generateTOTP", { enumerable: true, get: function () { return otp_js_2.generateTOTP; } });
Object.defineProperty(exports, "verifyTOTP", { enumerable: true, get: function () { return otp_js_2.verifyTOTP; } });
Object.defineProperty(exports, "generateHOTP", { enumerable: true, get: function () { return otp_js_2.generateHOTP; } });
Object.defineProperty(exports, "totpKeyUri", { enumerable: true, get: function () { return otp_js_2.totpKeyUri; } });
Object.defineProperty(exports, "toBase32", { enumerable: true, get: function () { return otp_js_2.toBase32; } });
Object.defineProperty(exports, "fromBase32", { enumerable: true, get: function () { return otp_js_2.fromBase32; } });
var multi_recipient_js_2 = require("./algorithms/multi-recipient.js");
Object.defineProperty(exports, "multiRecipientEncrypt", { enumerable: true, get: function () { return multi_recipient_js_2.multiRecipientEncrypt; } });
Object.defineProperty(exports, "multiRecipientDecrypt", { enumerable: true, get: function () { return multi_recipient_js_2.multiRecipientDecrypt; } });
Object.defineProperty(exports, "addRecipient", { enumerable: true, get: function () { return multi_recipient_js_2.addRecipient; } });
Object.defineProperty(exports, "removeRecipient", { enumerable: true, get: function () { return multi_recipient_js_2.removeRecipient; } });
var random_js_2 = require("./utils/random.js");
Object.defineProperty(exports, "secureRandomBytes", { enumerable: true, get: function () { return random_js_2.secureRandomBytes; } });
Object.defineProperty(exports, "secureRandomInt", { enumerable: true, get: function () { return random_js_2.secureRandomInt; } });
Object.defineProperty(exports, "secureRandomFloat", { enumerable: true, get: function () { return random_js_2.secureRandomFloat; } });
Object.defineProperty(exports, "secureRandomString", { enumerable: true, get: function () { return random_js_2.secureRandomString; } });
Object.defineProperty(exports, "secureRandomChoice", { enumerable: true, get: function () { return random_js_2.secureRandomChoice; } });
Object.defineProperty(exports, "secureRandomSample", { enumerable: true, get: function () { return random_js_2.secureRandomSample; } });
Object.defineProperty(exports, "secureRandomShuffle", { enumerable: true, get: function () { return random_js_2.secureRandomShuffle; } });
Object.defineProperty(exports, "securePassphrase", { enumerable: true, get: function () { return random_js_2.securePassphrase; } });
Object.defineProperty(exports, "CHARSETS", { enumerable: true, get: function () { return random_js_2.CHARSETS; } });
var batch_js_2 = require("./utils/batch.js");
Object.defineProperty(exports, "encryptBatch", { enumerable: true, get: function () { return batch_js_2.encryptBatch; } });
Object.defineProperty(exports, "decryptBatch", { enumerable: true, get: function () { return batch_js_2.decryptBatch; } });
Object.defineProperty(exports, "encryptBatchMixed", { enumerable: true, get: function () { return batch_js_2.encryptBatchMixed; } });
Object.defineProperty(exports, "decryptBatchMixed", { enumerable: true, get: function () { return batch_js_2.decryptBatchMixed; } });
Object.defineProperty(exports, "encryptBatchSafe", { enumerable: true, get: function () { return batch_js_2.encryptBatchSafe; } });
Object.defineProperty(exports, "decryptBatchSafe", { enumerable: true, get: function () { return batch_js_2.decryptBatchSafe; } });
var codec_js_1 = require("./utils/codec.js");
Object.defineProperty(exports, "base32Encode", { enumerable: true, get: function () { return codec_js_1.base32Encode; } });
Object.defineProperty(exports, "base32Decode", { enumerable: true, get: function () { return codec_js_1.base32Decode; } });
Object.defineProperty(exports, "hexEncode", { enumerable: true, get: function () { return codec_js_1.hexEncode; } });
Object.defineProperty(exports, "hexDecode", { enumerable: true, get: function () { return codec_js_1.hexDecode; } });
Object.defineProperty(exports, "base64Encode", { enumerable: true, get: function () { return codec_js_1.base64Encode; } });
Object.defineProperty(exports, "base64urlEncode", { enumerable: true, get: function () { return codec_js_1.base64urlEncode; } });
Object.defineProperty(exports, "base64Decode", { enumerable: true, get: function () { return codec_js_1.base64Decode; } });
Object.defineProperty(exports, "safeCompare", { enumerable: true, get: function () { return codec_js_1.safeCompare; } });
Object.defineProperty(exports, "convertEncoding", { enumerable: true, get: function () { return codec_js_1.convertEncoding; } });
var inspect_js_2 = require("./utils/inspect.js");
Object.defineProperty(exports, "inspectPayload", { enumerable: true, get: function () { return inspect_js_2.inspectPayload; } });
Object.defineProperty(exports, "inspectStreamHeader", { enumerable: true, get: function () { return inspect_js_2.inspectStreamHeader; } });
Object.defineProperty(exports, "inspectToken", { enumerable: true, get: function () { return inspect_js_2.inspectToken; } });
var zeroize_js_2 = require("./utils/zeroize.js");
Object.defineProperty(exports, "zeroize", { enumerable: true, get: function () { return zeroize_js_2.zeroize; } });
Object.defineProperty(exports, "zeroizeAll", { enumerable: true, get: function () { return zeroize_js_2.zeroizeAll; } });
Object.defineProperty(exports, "withZeroize", { enumerable: true, get: function () { return zeroize_js_2.withZeroize; } });
Object.defineProperty(exports, "createKeyMetadataStore", { enumerable: true, get: function () { return zeroize_js_2.createKeyMetadataStore; } });
Object.defineProperty(exports, "reEncrypt", { enumerable: true, get: function () { return zeroize_js_2.reEncrypt; } });
Object.defineProperty(exports, "reEncryptBatch", { enumerable: true, get: function () { return zeroize_js_2.reEncryptBatch; } });
Object.defineProperty(exports, "exportKeyToJWK", { enumerable: true, get: function () { return zeroize_js_2.exportKeyToJWK; } });
Object.defineProperty(exports, "importKeyFromJWK", { enumerable: true, get: function () { return zeroize_js_2.importKeyFromJWK; } });
Object.defineProperty(exports, "serializeKey", { enumerable: true, get: function () { return zeroize_js_2.serializeKey; } });
Object.defineProperty(exports, "deserializeKey", { enumerable: true, get: function () { return zeroize_js_2.deserializeKey; } });
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
        parts.push((0, env_js_1.encode)('ttl:'), expiryBytes);
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
class EncryptixClient {
    constructor(config = {}) {
        this.masterKey = (0, keys_js_1.resolveMasterKey)(config.key);
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
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const algo = options.algorithm ?? this.algorithm;
        const encoding = options.encoding ?? this.encoding;
        const extraAad = options.aad ? (typeof options.aad === 'string' ? (0, env_js_1.encode)(options.aad) : options.aad) : undefined;
        const aad = buildTTLAad(options.ttlSeconds, extraAad);
        let payload;
        if (algo === 'aes-256-gcm') {
            payload = await (0, aes_gcm_js_1.aesEncrypt)(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        }
        else if (algo === 'chacha20-poly1305') {
            payload = await (0, chacha20_js_1.chachaEncrypt)(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        }
        else {
            throw new errors_js_1.EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algorithm: ${algo}`);
        }
        const kv = new Uint8Array(2);
        new DataView(kv.buffer).setUint16(0, this.currentKeyVersion, false);
        const out = new Uint8Array(2 + payload.length);
        out.set(payload.slice(0, 2));
        out.set(kv, 2);
        out.set(payload.slice(2), 4);
        return (0, env_js_1.encodeOutput)(out, encoding);
    }
    async decrypt(payload, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const encoding = options.encoding ?? this.encoding;
        const extraAad = options.aad ? (typeof options.aad === 'string' ? (0, env_js_1.encode)(options.aad) : options.aad) : undefined;
        let data;
        try {
            data = (0, env_js_1.decodeInput)(payload, encoding);
        }
        catch (err) {
            throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Failed to decode payload.', err);
        }
        if (data.length < HEADER_SIZE + 12 + 16)
            throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Payload is too short.');
        const algoId = data[1];
        const keyVersion = new DataView(data.buffer, data.byteOffset + 2, 2).getUint16(0, false);
        const stripped = new Uint8Array(data.length - 2);
        stripped.set(data.slice(0, 2));
        stripped.set(data.slice(4), 2);
        const key = this.resolveDecryptionKey(keyVersion);
        if (algoId === aes_gcm_js_1.ALGO_ID)
            return (0, aes_gcm_js_1.aesDecrypt)(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
        if (algoId === chacha20_js_1.ALGO_ID)
            return (0, chacha20_js_1.chachaDecrypt)(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
        throw new errors_js_1.EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algo_id: 0x${algoId.toString(16)}`);
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
            throw new errors_js_1.EncryptixError('ENCRYPTION_FAILED', 'Failed to serialize object.', err);
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
            throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Failed to deserialize decrypted object.', err);
        }
        if (wrapper.exp !== undefined && Math.floor(Date.now() / 1000) > wrapper.exp) {
            throw new errors_js_1.EncryptixError('PAYLOAD_EXPIRED', `Payload expired ${Math.floor(Date.now() / 1000) - wrapper.exp}s ago.`);
        }
        return wrapper.d;
    }
    // ─── Batch ──────────────────────────────────────────────────────────────────
    async encryptBatch(items, purpose, options) {
        return (0, batch_js_1.encryptBatch)(this.encrypt.bind(this), items, purpose, options);
    }
    async decryptBatch(payloads, purpose, options) {
        return (0, batch_js_1.decryptBatch)(this.decrypt.bind(this), payloads, purpose, options);
    }
    async encryptBatchMixed(items) {
        return (0, batch_js_1.encryptBatchMixed)(this.encrypt.bind(this), items);
    }
    async decryptBatchMixed(items) {
        return (0, batch_js_1.decryptBatchMixed)(this.decrypt.bind(this), items);
    }
    async encryptBatchSafe(items, purpose, options) {
        return (0, batch_js_1.encryptBatchSafe)(this.encrypt.bind(this), items, purpose, options);
    }
    async decryptBatchSafe(payloads, purpose, options) {
        return (0, batch_js_1.decryptBatchSafe)(this.decrypt.bind(this), payloads, purpose, options);
    }
    // ─── Deterministic (AES-SIV) ─────────────────────────────────────────────
    async encryptDeterministic(plaintext, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const aad = options.aad ? (typeof options.aad === 'string' ? (0, env_js_1.encode)(options.aad) : options.aad) : undefined;
        const payload = await (0, aes_siv_js_1.sivEncrypt)(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
        return (0, env_js_1.encodeOutput)(payload, options.encoding ?? this.encoding);
    }
    async decryptDeterministic(payload, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        const aad = options.aad ? (typeof options.aad === 'string' ? (0, env_js_1.encode)(options.aad) : options.aad) : undefined;
        let data;
        try {
            data = (0, env_js_1.decodeInput)(payload, options.encoding ?? this.encoding);
        }
        catch (err) {
            throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Failed to decode deterministic payload.', err);
        }
        return (0, aes_siv_js_1.sivDecrypt)(data, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
    }
    // ─── Envelope ────────────────────────────────────────────────────────────
    async envelopeEncrypt(plaintext, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return (0, envelope_js_1.envelopeEncrypt)(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
    }
    async envelopeDecrypt(envelope, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return (0, envelope_js_1.envelopeDecrypt)(envelope, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
    }
    // ─── Multi-Recipient ─────────────────────────────────────────────────────
    async multiRecipientEncrypt(plaintext, recipients, options = {}) {
        return (0, multi_recipient_js_1.multiRecipientEncrypt)(plaintext, recipients, this.namespace, this.hashAlgorithm, options);
    }
    async multiRecipientDecrypt(envelope, recipientId, privateKeyPEM, options = {}) {
        return (0, multi_recipient_js_1.multiRecipientDecrypt)(envelope, recipientId, privateKeyPEM, this.namespace, this.hashAlgorithm, options);
    }
    addRecipient(envelope, existingId, existingPrivateKeyPEM, newRecipient) {
        return (0, multi_recipient_js_1.addRecipient)(envelope, existingId, existingPrivateKeyPEM, newRecipient);
    }
    removeRecipient(envelope, recipientId) {
        return (0, multi_recipient_js_1.removeRecipient)(envelope, recipientId);
    }
    // ─── Signed Tokens ────────────────────────────────────────────────────────
    async sign(payload, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return (0, signed_token_js_1.signToken)(payload, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    async verify(token, purpose, options = {}) {
        if (!purpose)
            throw new errors_js_1.EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
        return (0, signed_token_js_1.verifyToken)(token, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    // ─── Streaming ───────────────────────────────────────────────────────────
    encryptStream(options) {
        return (0, streaming_js_1.createEncryptStream)(this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    decryptStream(options) {
        return (0, streaming_js_1.createDecryptStream)(this.masterKey, this.namespace, this.hashAlgorithm, options);
    }
    // ─── RSA ─────────────────────────────────────────────────────────────────
    async generateRSAKeyPair(modulusLength = 2048) { return (0, rsa_js_1.generateRSAKeyPair)(modulusLength); }
    async encryptRSA(plaintext, publicKeyPEM, encoding = this.encoding) { return (0, rsa_js_1.rsaEncrypt)(plaintext, publicKeyPEM, encoding); }
    async decryptRSA(ciphertext, privateKeyPEM, encoding = this.encoding) { return (0, rsa_js_1.rsaDecrypt)(ciphertext, privateKeyPEM, encoding); }
    async generateRSAPSSKeyPair(modulusLength = 2048) { return (0, rsa_sign_js_1.generateRSAPSSKeyPair)(modulusLength); }
    async signRSA(data, privateKeyPEM, encoding = this.encoding) { return (0, rsa_sign_js_1.rsaPssSign)(data, privateKeyPEM, 'SHA-256', encoding); }
    async verifyRSA(data, signature, publicKeyPEM, encoding = this.encoding) { return (0, rsa_sign_js_1.rsaPssVerify)(data, signature, publicKeyPEM, 'SHA-256', encoding); }
    // ─── ECDH / ECDSA ────────────────────────────────────────────────────────
    async generateECDHKeyPair(curve = 'P-256') { return (0, ecdh_js_1.generateECDHKeyPair)(curve); }
    async deriveSharedSecret(privateKeyPEM, peerPublicKeyPEM, curve = 'P-256') { return (0, ecdh_js_1.deriveSharedSecret)(privateKeyPEM, peerPublicKeyPEM, curve); }
    async generateECDSAKeyPair(curve = 'P-256') { return (0, ecdh_js_1.generateECDSAKeyPair)(curve); }
    async signECDSA(data, privateKeyPEM, curve = 'P-256', encoding = this.encoding) { return (0, ecdh_js_1.ecdsaSign)(data, privateKeyPEM, curve, encoding); }
    async verifyECDSA(data, signature, publicKeyPEM, curve = 'P-256', encoding = this.encoding) { return (0, ecdh_js_1.ecdsaVerify)(data, signature, publicKeyPEM, curve, encoding); }
    // ─── TOTP / HOTP ────────────────────────────────────────────────────────
    generateTOTPSecret(bytes = 20) { return (0, otp_js_1.generateTOTPSecret)(bytes); }
    totpKeyUri(secret, account, issuer, options) { return (0, otp_js_1.totpKeyUri)(secret, account, issuer, options); }
    async generateTOTP(secret, options) { return (0, otp_js_1.generateTOTP)(secret, options); }
    async generateHOTP(secret, counter, options) { return (0, otp_js_1.generateHOTP)(secret, counter, options); }
    async verifyTOTP(code, secret, options) { return (0, otp_js_1.verifyTOTP)(code, secret, options); }
    // ─── Password KDF ────────────────────────────────────────────────────────
    async deriveKeyFromPassword(password, purpose, options = {}) { return (0, password_js_1.deriveKeyFromPassword)(password, purpose, options); }
    // ─── Hashing / HMAC ──────────────────────────────────────────────────────
    async hash(input, algorithm = this.hashAlgorithm, encoding = 'hex') { return (0, tokens_js_1.hash)(input, algorithm, encoding); }
    async hmac(message, keyHex = this.masterKey, algorithm = this.hashAlgorithm, encoding = 'hex') { return (0, tokens_js_1.hmac)(message, keyHex, algorithm, encoding); }
    async verifyHmac(message, signature, keyHex = this.masterKey, algorithm = this.hashAlgorithm, encoding = 'hex') { return (0, tokens_js_1.verifyHmac)(message, keyHex, signature, algorithm, encoding); }
    // ─── Inspect ────────────────────────────────────────────────────────────
    inspectPayload(payload, encoding) { return (0, inspect_js_1.inspectPayload)(payload, encoding ?? this.encoding); }
    inspectStreamHeader(headerBytes) { return (0, inspect_js_1.inspectStreamHeader)(headerBytes); }
    inspectToken(token) { return (0, inspect_js_1.inspectToken)(token); }
    // ─── Key Operations ───────────────────────────────────────────────────────
    async keyFingerprint() {
        const digest = await (0, tokens_js_2.hash)(new TextEncoder().encode(this.masterKey), 'sha256', 'hex');
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
        return (0, zeroize_js_1.reEncrypt)(payload, { decryptFn: this.decrypt.bind(this), purpose: fromPurpose, options: options?.fromOptions }, { encryptFn: this.encrypt.bind(this), purpose: toPurpose, options: options?.toOptions });
    }
    async exportKey(format = 'hex') { return (0, zeroize_js_1.serializeKey)(this.masterKey, format); }
    // ─── Token / ID Generation ───────────────────────────────────────────────
    generateToken(bytes = 32, encoding = 'hex') { return (0, tokens_js_1.generateToken)(bytes, encoding); }
    generateApiKey(prefix = 'key', bytes = 32) { return (0, tokens_js_1.generateApiKey)(prefix, bytes); }
    generateUUID() { return (0, tokens_js_1.generateUUID)(); }
    // ─── Secure Random ────────────────────────────────────────────────────────
    randomBytes(n) { return (0, random_js_1.secureRandomBytes)(n); }
    randomInt(min, max) { return (0, random_js_1.secureRandomInt)(min, max); }
    randomFloat() { return (0, random_js_1.secureRandomFloat)(); }
    randomString(length, charset) { return (0, random_js_1.secureRandomString)(length, charset); }
    randomChoice(array) { return (0, random_js_1.secureRandomChoice)(array); }
    randomSample(array, n) { return (0, random_js_1.secureRandomSample)(array, n); }
    randomShuffle(array) { return (0, random_js_1.secureRandomShuffle)(array); }
    // ─── Private ─────────────────────────────────────────────────────────────
    resolveDecryptionKey(keyVersion) {
        if (keyVersion === 1 && Object.keys(this.keychain).length === 0)
            return this.masterKey;
        if (keyVersion === this.currentKeyVersion)
            return this.masterKey;
        return (0, keys_js_1.resolveKeychainKey)(this.keychain, keyVersion);
    }
}
exports.EncryptixClient = EncryptixClient;
function createEncryptix(config = {}) {
    return new EncryptixClient(config);
}
//# sourceMappingURL=client.js.map