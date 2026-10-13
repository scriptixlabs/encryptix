/**
 * EncryptixClient — primary interface for @scriptixlabs/encryptix
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
import { generateTOTPSecret, generateTOTP, verifyTOTP, generateHOTP, totpKeyUri, toBase32, fromBase32 } from './algorithms/otp.js';
import { multiRecipientEncrypt, multiRecipientDecrypt, addRecipient, removeRecipient } from './algorithms/multi-recipient.js';
import { hash, hmac, verifyHmac, generateToken, generateApiKey, generateUUID } from './utils/tokens.js';
import { generateMasterKey, resolveMasterKey, resolveKeychainKey } from './utils/keys.js';
import { encodeOutput, decodeInput, encode } from './utils/env.js';
import { EncryptixError } from './utils/errors.js';
import { hash as hashFn } from './utils/tokens.js';
import { secureRandomBytes, secureRandomInt, secureRandomFloat, secureRandomString, secureRandomChoice, secureRandomSample, secureRandomShuffle, securePassphrase, CHARSETS } from './utils/random.js';
import { encryptBatch, decryptBatch, encryptBatchMixed, decryptBatchMixed, encryptBatchSafe, decryptBatchSafe } from './utils/batch.js';
import { base32Encode, base32Decode, hexEncode, hexDecode, base64Encode, base64urlEncode, base64Decode, safeCompare, convertEncoding } from './utils/codec.js';
import { inspectPayload, inspectStreamHeader, inspectToken } from './utils/inspect.js';
import { zeroize, zeroizeAll, withZeroize, createKeyMetadataStore, reEncrypt, reEncryptBatch, exportKeyToJWK, importKeyFromJWK, serializeKey, deserializeKey } from './utils/zeroize.js';

import type {
  EncryptixConfig, EncryptOptions, DecryptOptions, EncryptObjectOptions, DecryptObjectOptions,
  SymmetricAlgorithm, Encoding, HashAlgorithm, RSAKeyPair, KeyPurpose,
  EnvelopePayload, EnvelopeEncryptOptions, EnvelopeDecryptOptions,
  SignTokenOptions, VerifyTokenOptions, VerifyTokenResult,
  StreamEncryptOptions, StreamDecryptOptions,
  DeriveKeyFromPasswordOptions, DerivedPasswordKey,
  DeterministicEncryptOptions, DeterministicDecryptOptions,
  KeyFingerprint, ECCurve, ECKeyPair, TOTPOptions, HOTPOptions, TOTPVerifyResult,
  RecipientKey, MultiRecipientEnvelope, MultiRecipientOptions,
  BatchResult, BatchEncryptItem, KeyMetadataStore, ReEncryptOptions, KeyExportFormat,
  PayloadInspection, StreamHeaderInspection,
  HmacKey, HmacOptions, HmacOutputEncoding,
} from './types/index.js';

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
export type * from './types/index.js';

const HEADER_SIZE = 4;

function buildTTLAad(ttlSeconds: number | undefined, extraAad: Uint8Array | undefined): Uint8Array | undefined {
  if (ttlSeconds === undefined && extraAad === undefined) return undefined;
  const parts: Uint8Array[] = [];
  if (ttlSeconds !== undefined) {
    const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
    const expiryBytes = new Uint8Array(8);
    new DataView(expiryBytes.buffer).setUint32(0, Math.floor(expiry / 0x100000000), false);
    new DataView(expiryBytes.buffer).setUint32(4, expiry >>> 0, false);
    parts.push(encode('ttl:'), expiryBytes);
  }
  if (extraAad) parts.push(extraAad);
  const total = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

export class EncryptixClient {
  private readonly masterKey: string;
  private readonly algorithm: SymmetricAlgorithm;
  private readonly encoding: Encoding;
  private readonly hashAlgorithm: HashAlgorithm;
  private readonly keychain: Record<number, string>;
  private readonly namespace: string;
  private readonly currentKeyVersion: number;

  constructor(config: EncryptixConfig = {}) {
    this.masterKey     = resolveMasterKey(config.key);
    this.algorithm     = config.algorithm     ?? 'aes-256-gcm';
    this.encoding      = config.encoding      ?? 'base64';
    this.hashAlgorithm = config.hashAlgorithm ?? 'sha256';
    this.namespace     = config.namespace     ?? 'encryptix';
    this.keychain      = config.keychain      ?? {};
    const versions = Object.keys(this.keychain).map(Number);
    this.currentKeyVersion = versions.length > 0 ? Math.max(...versions) + 1 : 1;
  }

  // ─── Symmetric ──────────────────────────────────────────────────────────────

  async encrypt(plaintext: string, purpose: KeyPurpose, options: EncryptOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    const algo = options.algorithm ?? this.algorithm;
    const encoding = options.encoding ?? this.encoding;
    const extraAad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    const aad = buildTTLAad(options.ttlSeconds, extraAad);
    let payload: Uint8Array;
    if (algo === 'aes-256-gcm') {
      payload = await aesEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
    } else if (algo === 'chacha20-poly1305') {
      payload = await chachaEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
    } else {
      throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algorithm: ${algo}`);
    }
    const kv = new Uint8Array(2);
    new DataView(kv.buffer).setUint16(0, this.currentKeyVersion, false);
    const out = new Uint8Array(2 + payload.length);
    out.set(payload.slice(0, 2)); out.set(kv, 2); out.set(payload.slice(2), 4);
    return encodeOutput(out, encoding);
  }

  async decrypt(payload: string, purpose: KeyPurpose, options: DecryptOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    const encoding = options.encoding ?? this.encoding;
    const extraAad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    let data: Uint8Array;
    try { data = decodeInput(payload, encoding); }
    catch (err) { throw new EncryptixError('INVALID_PAYLOAD', 'Failed to decode payload.', err); }
    if (data.length < HEADER_SIZE + 12 + 16) throw new EncryptixError('INVALID_PAYLOAD', 'Payload is too short.');
    const algoId = data[1];
    const keyVersion = new DataView(data.buffer, data.byteOffset + 2, 2).getUint16(0, false);
    const stripped = new Uint8Array(data.length - 2);
    stripped.set(data.slice(0, 2)); stripped.set(data.slice(4), 2);
    const key = this.resolveDecryptionKey(keyVersion);
    if (algoId === AES_ALGO_ID) return aesDecrypt(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
    if (algoId === CHACHA_ALGO_ID) return chachaDecrypt(stripped, key, purpose, this.namespace, this.hashAlgorithm, extraAad);
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unknown algo_id: 0x${algoId.toString(16)}`);
  }

  // ─── Object ─────────────────────────────────────────────────────────────────

  async encryptObject<T>(value: T, purpose: KeyPurpose, options: EncryptObjectOptions = {}): Promise<string> {
    const serialize = options.serialize ?? JSON.stringify;
    const wrapper = { d: value, ...(options.ttlSeconds !== undefined ? { exp: Math.floor(Date.now()/1000) + options.ttlSeconds } : {}) };
    let serialized: string;
    try { serialized = serialize(wrapper); }
    catch (err) { throw new EncryptixError('ENCRYPTION_FAILED', 'Failed to serialize object.', err); }
    return this.encrypt(serialized, purpose, { algorithm: options.algorithm, encoding: options.encoding, aad: options.aad });
  }

  async decryptObject<T>(payload: string, purpose: KeyPurpose, options: DecryptObjectOptions = {}): Promise<T> {
    const raw = await this.decrypt(payload, purpose, options);
    const deserialize = options.deserialize ?? JSON.parse;
    let wrapper: { d: T; exp?: number };
    try { wrapper = deserialize(raw) as { d: T; exp?: number }; }
    catch (err) { throw new EncryptixError('INVALID_PAYLOAD', 'Failed to deserialize decrypted object.', err); }
    if (wrapper.exp !== undefined && Math.floor(Date.now()/1000) > wrapper.exp) {
      throw new EncryptixError('PAYLOAD_EXPIRED', `Payload expired ${Math.floor(Date.now()/1000) - wrapper.exp}s ago.`);
    }
    return wrapper.d;
  }

  // ─── Batch ──────────────────────────────────────────────────────────────────

  async encryptBatch(items: string[], purpose: KeyPurpose, options?: EncryptOptions): Promise<string[]> {
    return encryptBatch(this.encrypt.bind(this), items, purpose, options);
  }
  async decryptBatch(payloads: string[], purpose: KeyPurpose, options?: DecryptOptions): Promise<string[]> {
    return decryptBatch(this.decrypt.bind(this), payloads, purpose, options);
  }
  async encryptBatchMixed(items: BatchEncryptItem[]): Promise<string[]> {
    return encryptBatchMixed(this.encrypt.bind(this), items);
  }
  async decryptBatchMixed(items: { payload: string; purpose: string; options?: DecryptOptions }[]): Promise<string[]> {
    return decryptBatchMixed(this.decrypt.bind(this), items);
  }
  async encryptBatchSafe(items: string[], purpose: KeyPurpose, options?: EncryptOptions): Promise<BatchResult<string>[]> {
    return encryptBatchSafe(this.encrypt.bind(this), items, purpose, options);
  }
  async decryptBatchSafe(payloads: string[], purpose: KeyPurpose, options?: DecryptOptions): Promise<BatchResult<string>[]> {
    return decryptBatchSafe(this.decrypt.bind(this), payloads, purpose, options);
  }

  // ─── Deterministic (AES-SIV) ─────────────────────────────────────────────

  async encryptDeterministic(plaintext: string, purpose: KeyPurpose, options: DeterministicEncryptOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    const payload = await sivEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
    return encodeOutput(payload, options.encoding ?? this.encoding);
  }

  async decryptDeterministic(payload: string, purpose: KeyPurpose, options: DeterministicDecryptOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    let data: Uint8Array;
    try { data = decodeInput(payload, options.encoding ?? this.encoding); }
    catch (err) { throw new EncryptixError('INVALID_PAYLOAD', 'Failed to decode deterministic payload.', err); }
    return sivDecrypt(data, this.masterKey, purpose, this.namespace, this.hashAlgorithm, aad);
  }

  // ─── Envelope ────────────────────────────────────────────────────────────

  async envelopeEncrypt(plaintext: string, purpose: KeyPurpose, options: EnvelopeEncryptOptions = {}): Promise<EnvelopePayload> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    return envelopeEncrypt(plaintext, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
  }
  async envelopeDecrypt(envelope: EnvelopePayload, purpose: KeyPurpose, options: EnvelopeDecryptOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    return envelopeDecrypt(envelope, this.masterKey, purpose, this.namespace, this.hashAlgorithm, options);
  }

  // ─── Multi-Recipient ─────────────────────────────────────────────────────

  async multiRecipientEncrypt(plaintext: string, recipients: RecipientKey[], options: MultiRecipientOptions = {}): Promise<MultiRecipientEnvelope> {
    return multiRecipientEncrypt(plaintext, recipients, this.namespace, this.hashAlgorithm, options);
  }
  async multiRecipientDecrypt(envelope: MultiRecipientEnvelope, recipientId: string, privateKeyPEM: string, options: MultiRecipientOptions = {}): Promise<string> {
    return multiRecipientDecrypt(envelope, recipientId, privateKeyPEM, this.namespace, this.hashAlgorithm, options);
  }
  addRecipient(envelope: MultiRecipientEnvelope, existingId: string, existingPrivateKeyPEM: string, newRecipient: RecipientKey): Promise<MultiRecipientEnvelope> {
    return addRecipient(envelope, existingId, existingPrivateKeyPEM, newRecipient);
  }
  removeRecipient(envelope: MultiRecipientEnvelope, recipientId: string): MultiRecipientEnvelope {
    return removeRecipient(envelope, recipientId);
  }

  // ─── Signed Tokens ────────────────────────────────────────────────────────

  async sign<T>(payload: T, purpose: KeyPurpose, options: SignTokenOptions = {}): Promise<string> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    return signToken(payload, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
  }
  async verify<T>(token: string, purpose: KeyPurpose, options: VerifyTokenOptions = {}): Promise<VerifyTokenResult<T>> {
    if (!purpose) throw new EncryptixError('INVALID_PURPOSE', 'purpose must be a non-empty string.');
    return verifyToken<T>(token, purpose, this.masterKey, this.namespace, this.hashAlgorithm, options);
  }

  // ─── Streaming ───────────────────────────────────────────────────────────

  encryptStream(options: StreamEncryptOptions): TransformStream<Uint8Array, Uint8Array> {
    return createEncryptStream(this.masterKey, this.namespace, this.hashAlgorithm, options);
  }
  decryptStream(options: StreamDecryptOptions): TransformStream<Uint8Array, Uint8Array> {
    return createDecryptStream(this.masterKey, this.namespace, this.hashAlgorithm, options);
  }

  // ─── RSA ─────────────────────────────────────────────────────────────────

  async generateRSAKeyPair(modulusLength: 2048 | 4096 = 2048): Promise<RSAKeyPair> { return generateRSAKeyPair(modulusLength); }
  async encryptRSA(plaintext: string, publicKeyPEM: string, encoding: Encoding = this.encoding): Promise<string> { return rsaEncrypt(plaintext, publicKeyPEM, encoding); }
  async decryptRSA(ciphertext: string, privateKeyPEM: string, encoding: Encoding = this.encoding): Promise<string> { return rsaDecrypt(ciphertext, privateKeyPEM, encoding); }
  async generateRSAPSSKeyPair(modulusLength: 2048 | 4096 = 2048): Promise<RSAKeyPair> { return generateRSAPSSKeyPair(modulusLength); }
  async signRSA(data: string | Uint8Array, privateKeyPEM: string, encoding: Encoding = this.encoding): Promise<string> { return rsaPssSign(data, privateKeyPEM, 'SHA-256', encoding); }
  async verifyRSA(data: string | Uint8Array, signature: string, publicKeyPEM: string, encoding: Encoding = this.encoding): Promise<boolean> { return rsaPssVerify(data, signature, publicKeyPEM, 'SHA-256', encoding); }

  // ─── ECDH / ECDSA ────────────────────────────────────────────────────────

  async generateECDHKeyPair(curve: ECCurve = 'P-256'): Promise<ECKeyPair> { return generateECDHKeyPair(curve); }
  async deriveSharedSecret(privateKeyPEM: string, peerPublicKeyPEM: string, curve: ECCurve = 'P-256'): Promise<string> { return deriveSharedSecret(privateKeyPEM, peerPublicKeyPEM, curve); }
  async generateECDSAKeyPair(curve: ECCurve = 'P-256'): Promise<ECKeyPair> { return generateECDSAKeyPair(curve); }
  async signECDSA(data: string | Uint8Array, privateKeyPEM: string, curve: ECCurve = 'P-256', encoding: Encoding = this.encoding): Promise<string> { return ecdsaSign(data, privateKeyPEM, curve, encoding); }
  async verifyECDSA(data: string | Uint8Array, signature: string, publicKeyPEM: string, curve: ECCurve = 'P-256', encoding: Encoding = this.encoding): Promise<boolean> { return ecdsaVerify(data, signature, publicKeyPEM, curve, encoding); }

  // ─── TOTP / HOTP ────────────────────────────────────────────────────────

  generateTOTPSecret(bytes = 20): string { return generateTOTPSecret(bytes); }
  totpKeyUri(secret: string, account: string, issuer: string, options?: Pick<TOTPOptions, 'digits' | 'period'>): string { return totpKeyUri(secret, account, issuer, options); }
  async generateTOTP(secret: string, options?: TOTPOptions): Promise<string> { return generateTOTP(secret, options); }
  async generateHOTP(secret: string, counter: number, options?: HOTPOptions): Promise<string> { return generateHOTP(secret, counter, options); }
  async verifyTOTP(code: string, secret: string, options?: TOTPOptions & { skew?: number }): Promise<TOTPVerifyResult> { return verifyTOTP(code, secret, options); }

  // ─── Password KDF ────────────────────────────────────────────────────────

  async deriveKeyFromPassword(password: string, purpose: string, options: DeriveKeyFromPasswordOptions = {}): Promise<DerivedPasswordKey> { return deriveKeyFromPassword(password, purpose, options); }

  // ─── Hashing / HMAC ──────────────────────────────────────────────────────

  async hash(input: string | Uint8Array, algorithm: HashAlgorithm = this.hashAlgorithm, encoding: 'hex' | 'base64' | 'base64url' = 'hex'): Promise<string> { return hash(input, algorithm, encoding); }

  /**
   * HMAC a message.
   *
   * **Master-key fallback (intentional, 1.0.0 behaviour):** when `key` is
   * omitted (`undefined`), the client's raw master key is used as the HMAC key.
   * This is meant for signing your own data; for third-party webhooks always
   * pass the provider's secret explicitly, e.g.
   * `enc.hmac(body, secret, { keyEncoding: 'utf8', encoding: 'base64' })`.
   * Passing `keyEncoding` without a key throws, so a missing secret (e.g. an
   * unset env var) never silently falls back to the master key in that form.
   *
   * String keys are hex-decoded unless `keyEncoding` says otherwise.
   * The algorithm defaults to the client's `hashAlgorithm`.
   */
  async hmac(message: string | Uint8Array, key?: HmacKey, algorithm?: HashAlgorithm, encoding?: HmacOutputEncoding): Promise<string>;
  async hmac(message: string | Uint8Array, key: HmacKey | undefined, options: HmacOptions): Promise<string>;
  async hmac(message: string | Uint8Array, key?: HmacKey, algorithmOrOptions?: HashAlgorithm | HmacOptions, encoding?: HmacOutputEncoding): Promise<string> {
    const [k, opts] = this.resolveClientHmac(key, algorithmOrOptions, encoding);
    return hmac(message, k, opts);
  }

  /**
   * Constant-time HMAC verification. Same key rules (and master-key fallback)
   * as {@link EncryptixClient.hmac}.
   */
  async verifyHmac(message: string | Uint8Array, signature: string, key?: HmacKey, algorithm?: HashAlgorithm, encoding?: HmacOutputEncoding): Promise<boolean>;
  async verifyHmac(message: string | Uint8Array, signature: string, key: HmacKey | undefined, options: HmacOptions): Promise<boolean>;
  async verifyHmac(message: string | Uint8Array, signature: string, key?: HmacKey, algorithmOrOptions?: HashAlgorithm | HmacOptions, encoding?: HmacOutputEncoding): Promise<boolean> {
    const [k, opts] = this.resolveClientHmac(key, algorithmOrOptions, encoding);
    return verifyHmac(message, k, signature, opts);
  }

  private resolveClientHmac(
    key: HmacKey | undefined,
    algorithmOrOptions: HashAlgorithm | HmacOptions | undefined,
    encoding: HmacOutputEncoding | undefined,
  ): [HmacKey, HmacOptions] {
    const raw: HmacOptions =
      typeof algorithmOrOptions === 'object' && algorithmOrOptions !== null
        ? algorithmOrOptions
        : { algorithm: algorithmOrOptions, encoding };
    const opts: HmacOptions = { ...raw, algorithm: raw.algorithm ?? this.hashAlgorithm };
    if (key === undefined) {
      if (raw.keyEncoding !== undefined) {
        throw new EncryptixError(
          'INVALID_KEY',
          'keyEncoding was given but no HMAC key was passed. Refusing to fall back to the master key.',
        );
      }
      return [this.masterKey, { ...opts, keyEncoding: 'hex' }];
    }
    return [key, opts];
  }

  // ─── Inspect ────────────────────────────────────────────────────────────

  inspectPayload(payload: string, encoding?: Encoding): PayloadInspection { return inspectPayload(payload, encoding ?? this.encoding); }
  inspectStreamHeader(headerBytes: Uint8Array): StreamHeaderInspection { return inspectStreamHeader(headerBytes); }
  inspectToken(token: string): ReturnType<typeof inspectToken> { return inspectToken(token); }

  // ─── Key Operations ───────────────────────────────────────────────────────

  async keyFingerprint(): Promise<KeyFingerprint> {
    const digest = await hashFn(new TextEncoder().encode(this.masterKey), 'sha256', 'hex');
    return { fingerprint: digest.slice(0, 16), version: this.currentKeyVersion };
  }
  rotate(newMasterKeyHex: string): EncryptixClient {
    return new EncryptixClient({
      key: newMasterKeyHex, algorithm: this.algorithm, encoding: this.encoding,
      hashAlgorithm: this.hashAlgorithm, namespace: this.namespace,
      keychain: { ...this.keychain, [this.currentKeyVersion]: this.masterKey },
    });
  }
  async reEncrypt(payload: string, fromPurpose: string, toPurpose: string, options?: { fromOptions?: DecryptOptions; toOptions?: EncryptOptions }): Promise<string> {
    return reEncrypt(payload,
      { decryptFn: this.decrypt.bind(this), purpose: fromPurpose, options: options?.fromOptions },
      { encryptFn: this.encrypt.bind(this), purpose: toPurpose, options: options?.toOptions },
    );
  }
  async exportKey(format: KeyExportFormat = 'hex'): Promise<string> { return serializeKey(this.masterKey, format); }

  // ─── Token / ID Generation ───────────────────────────────────────────────

  generateToken(bytes = 32, encoding: 'hex' | 'base64' | 'base64url' = 'hex'): string { return generateToken(bytes, encoding); }
  generateApiKey(prefix = 'key', bytes = 32): string { return generateApiKey(prefix, bytes); }
  generateUUID(): string { return generateUUID(); }

  // ─── Secure Random ────────────────────────────────────────────────────────

  randomBytes(n: number): Uint8Array { return secureRandomBytes(n); }
  randomInt(min: number, max: number): number { return secureRandomInt(min, max); }
  randomFloat(): number { return secureRandomFloat(); }
  randomString(length: number, charset?: string): string { return secureRandomString(length, charset); }
  randomChoice<T>(array: readonly T[]): T { return secureRandomChoice(array); }
  randomSample<T>(array: readonly T[], n: number): T[] { return secureRandomSample(array, n); }
  randomShuffle<T>(array: readonly T[]): T[] { return secureRandomShuffle(array); }

  // ─── Private ─────────────────────────────────────────────────────────────

  private resolveDecryptionKey(keyVersion: number): string {
    if (keyVersion === 1 && Object.keys(this.keychain).length === 0) return this.masterKey;
    if (keyVersion === this.currentKeyVersion) return this.masterKey;
    return resolveKeychainKey(this.keychain, keyVersion);
  }
}

export function createEncryptix(config: EncryptixConfig = {}): EncryptixClient {
  return new EncryptixClient(config);
}
