// ─────────────────────────────────────────────────────────────────────────────
// @ppabari/encryptix — Core Types
// ─────────────────────────────────────────────────────────────────────────────

/** Supported symmetric encryption algorithms */
export type SymmetricAlgorithm = 'aes-256-gcm' | 'chacha20-poly1305';

/** Supported asymmetric encryption algorithms */
export type AsymmetricAlgorithm = 'rsa-oaep-sha256';

/** All supported algorithms */
export type Algorithm = SymmetricAlgorithm | AsymmetricAlgorithm;

/** Supported hash algorithms for HKDF and HMAC */
export type HashAlgorithm = 'sha256' | 'sha384' | 'sha512';

/** Supported output encodings */
export type Encoding = 'base64' | 'base64url' | 'hex';

/**
 * Purpose string used for HKDF key derivation and AAD.
 * Scopes a key to a specific use case, preventing cross-purpose attacks.
 *
 * @example 'user:session', 'payment:card', 'auth:refresh-token'
 */
export type KeyPurpose = string;

// ─── Payload Structure ────────────────────────────────────────────────────────

/** Internal binary layout version */
export type PayloadVersion = 1;

/** Decoded representation of an encrypted payload */
export interface DecodedPayload {
  version: PayloadVersion;
  algorithm: SymmetricAlgorithm;
  iv: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
  purpose: string;
}

// ─── Configuration ────────────────────────────────────────────────────────────

/** Options passed to the EncryptixClient constructor */
export interface EncryptixConfig {
  /**
   * Primary encryption key as a 64-char hex string (32 bytes).
   * Defaults to `process.env.ENCRYPTIX_KEY` if not provided.
   */
  key?: string;

  /**
   * Default algorithm to use for symmetric encryption.
   * @default 'aes-256-gcm'
   */
  algorithm?: SymmetricAlgorithm;

  /**
   * Default output encoding for encrypted payloads.
   * @default 'base64'
   */
  encoding?: Encoding;

  /**
   * Default hash algorithm used in HKDF key derivation.
   * @default 'sha256'
   */
  hashAlgorithm?: HashAlgorithm;

  /**
   * Key rotation map: maps a key version (number) to its hex key string.
   * Used to decrypt payloads encrypted with older keys while still
   * encrypting with the current primary key.
   *
   * @example { 1: 'aabbcc...', 2: 'ddeeff...' }
   */
  keychain?: Record<number, string>;

  /**
   * Custom namespace/prefix used in HKDF info string.
   * @default 'encryptix'
   */
  namespace?: string;
}

/** Options per encrypt() call — override config defaults */
export interface EncryptOptions {
  algorithm?: SymmetricAlgorithm;
  encoding?: Encoding;
  /** Extra data to include in AAD beyond the purpose string */
  aad?: string | Uint8Array;
  /**
   * TTL in seconds. If set, the payload will be rejected after this many
   * seconds from the time of encryption. The expiry is embedded in AAD
   * so it is authenticated and cannot be stripped or altered.
   */
  ttlSeconds?: number;
}

/** Options per decrypt() call */
export interface DecryptOptions {
  encoding?: Encoding;
  /** Must match the AAD used during encryption */
  aad?: string | Uint8Array;
}

// ─── Object encryption ───────────────────────────────────────────────────────

/** Options for encryptObject / decryptObject */
export interface EncryptObjectOptions extends EncryptOptions {
  /** Custom serializer. Default: JSON.stringify */
  serialize?: (value: unknown) => string;
}

export interface DecryptObjectOptions extends DecryptOptions {
  /** Custom deserializer. Default: JSON.parse */
  deserialize?: (raw: string) => unknown;
}

// ─── RSA ─────────────────────────────────────────────────────────────────────

export interface RSAKeyPair {
  publicKey: string;   // PEM
  privateKey: string;  // PEM
}

export interface RSAEncryptOptions {
  encoding?: Encoding;
}

// ─── Key Derivation ───────────────────────────────────────────────────────────

export interface DeriveKeyOptions {
  keyMaterial?: string | Uint8Array;
  salt?: string | Uint8Array;
  info?: string;
  length?: number;
  hash?: HashAlgorithm;
}

// ─── Password-Based Key Derivation ───────────────────────────────────────────

/**
 * Supported password KDF algorithms.
 * - `scrypt`  — Node.js only. Memory-hard, strong against GPU attacks. Recommended for Node.
 * - `pbkdf2`  — Universal (Web Crypto). Use in browsers and edge runtimes.
 */
export type PasswordKDFAlgorithm = 'scrypt' | 'pbkdf2';

export interface DeriveKeyFromPasswordOptions {
  /**
   * KDF algorithm. Defaults to 'scrypt' in Node, 'pbkdf2' elsewhere.
   */
  algorithm?: PasswordKDFAlgorithm;
  /**
   * Salt as a hex string. If omitted, a fresh random salt is generated.
   * You MUST store and reuse the salt to derive the same key again.
   */
  saltHex?: string;
  /**
   * scrypt N parameter (CPU/memory cost). Default: 2^17 (131072).
   * Must be a power of 2.
   */
  scryptN?: number;
  /** scrypt r parameter (block size). Default: 8 */
  scryptR?: number;
  /** scrypt p parameter (parallelism). Default: 1 */
  scryptP?: number;
  /** PBKDF2 iteration count. Default: 600000 (OWASP 2023 recommendation) */
  pbkdf2Iterations?: number;
  /** Output key length in bytes. Default: 32 (256 bits) */
  keyLength?: number;
}

export interface DerivedPasswordKey {
  /** The derived key as a 64-char hex string, ready to pass to EncryptixClient */
  keyHex: string;
  /** Salt used during derivation — store this alongside the encrypted data */
  saltHex: string;
  /** Algorithm used, so you can re-derive with the same params */
  algorithm: PasswordKDFAlgorithm;
  /** KDF parameters used — needed to re-derive the same key */
  params: {
    scryptN?: number;
    scryptR?: number;
    scryptP?: number;
    pbkdf2Iterations?: number;
    keyLength: number;
  };
}

// ─── Envelope Encryption ─────────────────────────────────────────────────────

/**
 * An envelope-encrypted payload.
 * The DEK (Data Encryption Key) is wrapped by the KEK (Key Encryption Key).
 * The actual data is encrypted with the DEK.
 */
export interface EnvelopePayload {
  /** Encrypted DEK, wrapped with the KEK */
  wrappedDek: string;
  /** Encrypted data, encrypted with the DEK */
  ciphertext: string;
  /** Algorithm used for DEK wrapping (AES-KW) */
  wrapAlgorithm: 'AES-KW';
  /** Algorithm used for data encryption */
  dataAlgorithm: SymmetricAlgorithm;
  /** Key fingerprint of the KEK used — helps identify which KEK to use during decryption */
  kekFingerprint: string;
  /** Payload version */
  version: 1;
}

export interface EnvelopeEncryptOptions {
  dataAlgorithm?: SymmetricAlgorithm;
  encoding?: Encoding;
  aad?: string | Uint8Array;
  ttlSeconds?: number;
}

export interface EnvelopeDecryptOptions {
  encoding?: Encoding;
  aad?: string | Uint8Array;
}

// ─── Signed Tokens ───────────────────────────────────────────────────────────

/**
 * A signed token payload — a lightweight, self-contained signed structure.
 * Think: JWT without the ecosystem complexity.
 */
export interface SignedToken<T = unknown> {
  /** The token data */
  payload: T;
  /** Unix timestamp (seconds) when the token was issued */
  iat: number;
  /** Unix timestamp (seconds) when the token expires. Omitted if no TTL. */
  exp?: number;
  /** Purpose/audience — prevents a token for one use from being used for another */
  purpose: string;
}

export interface SignTokenOptions {
  /** TTL in seconds. Omit for tokens that never expire. */
  ttlSeconds?: number;
  /** Output encoding. Default: 'base64url' (URL-safe, no padding) */
  encoding?: Encoding;
}

export interface VerifyTokenOptions {
  /** Input encoding. Default: 'base64url' */
  encoding?: Encoding;
  /** If true, expired tokens throw instead of returning null. Default: false */
  throwOnExpiry?: boolean;
}

export interface VerifyTokenResult<T = unknown> {
  valid: boolean;
  payload: T | null;
  /** 'valid' | 'expired' | 'invalid_signature' | 'malformed' */
  reason: 'valid' | 'expired' | 'invalid_signature' | 'malformed';
  /** Remaining TTL in seconds. Negative if expired. */
  remainingTtl?: number;
}

// ─── Streaming ───────────────────────────────────────────────────────────────

export interface StreamEncryptOptions {
  purpose: string;
  algorithm?: SymmetricAlgorithm;
  aad?: string | Uint8Array;
  /**
   * Chunk size for streaming encryption in bytes.
   * Each chunk is independently authenticated to prevent truncation attacks.
   * Default: 64 KiB
   */
  chunkSize?: number;
}

export interface StreamDecryptOptions {
  purpose: string;
  aad?: string | Uint8Array;
}

// ─── Key Fingerprint ─────────────────────────────────────────────────────────

export interface KeyFingerprint {
  /** First 8 bytes of SHA-256(key), hex encoded — non-reversible short identifier */
  fingerprint: string;
  /** Key version in the current client (1 = primary, >1 = from keychain) */
  version: number;
}

// ─── Deterministic Encryption (AES-SIV) ─────────────────────────────────────

export interface DeterministicEncryptOptions {
  encoding?: Encoding;
  /** Additional authenticated data bound to the ciphertext */
  aad?: string | Uint8Array;
}

export interface DeterministicDecryptOptions {
  encoding?: Encoding;
  aad?: string | Uint8Array;
}

// ─── Hashing / Tokens ────────────────────────────────────────────────────────

export interface HashOptions {
  algorithm?: HashAlgorithm;
  encoding?: 'hex' | 'base64' | 'base64url';
}

export interface HmacOptions {
  algorithm?: HashAlgorithm;
  encoding?: 'hex' | 'base64' | 'base64url';
}

// ─── Errors ───────────────────────────────────────────────────────────────────

export type EncryptixErrorCode =
  | 'INVALID_KEY'
  | 'INVALID_PAYLOAD'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_ALGORITHM'
  | 'DECRYPTION_FAILED'
  | 'ENCRYPTION_FAILED'
  | 'KEY_NOT_FOUND'
  | 'INVALID_PURPOSE'
  | 'RSA_KEY_ERROR'
  | 'ENVIRONMENT_UNSUPPORTED'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'PAYLOAD_EXPIRED'
  | 'PASSWORD_KDF_FAILED'
  | 'ENVELOPE_ERROR'
  | 'STREAM_ERROR'
  | 'ECDH_ERROR'
  | 'ECDSA_ERROR'
  | 'RSA_SIGN_ERROR'
  | 'CODEC_ERROR'
  | 'INVALID_INPUT'
  | 'OTP_ERROR';

// ─── ECDH / ECDSA ─────────────────────────────────────────────────────────────

export type ECCurve = 'P-256' | 'P-384' | 'P-521';

export interface ECKeyPair {
  publicKey: string;   // PEM SPKI
  privateKey: string;  // PEM PKCS8
  curve: ECCurve;
}

export interface ECPublicKey {
  publicKey: string;
  curve: ECCurve;
}

// ─── RSA-PSS ──────────────────────────────────────────────────────────────────

export type RSAPSSHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

// ─── OTP ─────────────────────────────────────────────────────────────────────

export interface TOTPOptions {
  /** Number of digits. Default: 6 */
  digits?: number;
  /** Time step in seconds. Default: 30 */
  period?: number;
  /** Override timestamp (ms since epoch) for testing */
  timestamp?: number;
}

export interface HOTPOptions {
  /** Number of digits. Default: 6 */
  digits?: number;
}

export interface TOTPVerifyResult {
  /** Whether the code is valid */
  valid: boolean;
  /** Counter delta that matched (-skew to +skew, or null if invalid) */
  delta: number | null;
  /** Seconds remaining in the current TOTP window */
  remainingSeconds: number;
}

// ─── Multi-Recipient Envelope ─────────────────────────────────────────────────

export interface RecipientKey {
  /** Identifier for this recipient (e.g. email, user ID) */
  id: string;
  /** RSA public key in PEM (SPKI) format */
  publicKeyPEM: string;
}

export interface MultiRecipientEnvelope {
  version: 1;
  recipients: Array<{ id: string; wrappedDek: string }>;
  ciphertext: string;
  dataAlgorithm: SymmetricAlgorithm;
}

export interface MultiRecipientOptions {
  dataAlgorithm?: SymmetricAlgorithm;
  aad?: string | Uint8Array;
}

// ─── Random ───────────────────────────────────────────────────────────────────

export type RandomCharset =
  | 'alphanumeric'
  | 'lowercase'
  | 'uppercase'
  | 'hex'
  | 'numeric'
  | 'urlSafe'
  | 'readable'
  | 'printable';

// ─── Batch ────────────────────────────────────────────────────────────────────

export type BatchResult<T> =
  | { ok: true; value: T; index: number }
  | { ok: false; error: import('./index.js').EncryptixErrorCode extends never ? Error : Error; index: number };

export interface BatchEncryptItem {
  value: string;
  purpose: string;
  options?: EncryptOptions;
}

// ─── Codec ────────────────────────────────────────────────────────────────────

export type CodecEncoding = 'hex' | 'base64' | 'base64url' | 'base32';

// ─── Inspect ─────────────────────────────────────────────────────────────────

export interface PayloadInspection {
  payloadVersion: number;
  algorithm: string;
  keyVersion: number | null;
  isDeterministic: boolean;
  totalBytes: number;
  estimatedPlaintextBytes: number;
  encoding: Encoding;
}

export interface StreamHeaderInspection {
  valid: boolean;
  streamVersion: number;
  algorithm: string;
  chunkSize: number;
  headerBytes: number;
}

// ─── Key Metadata ─────────────────────────────────────────────────────────────

export interface KeyMetadata {
  version: number;
  keyHex: string;
  purpose?: string;
  algorithm?: SymmetricAlgorithm;
  createdAt: Date;
  rotatedAt?: Date;
  description?: string;
}

export interface KeyMetadataStore {
  register(version: number, metadata: Omit<KeyMetadata, 'version'>): void;
  get(version: number): KeyMetadata;
  has(version: number): boolean;
  versions(): number[];
  latest(): KeyMetadata | null;
  summary(): KeyMetadata[];
  toKeychain(): Record<number, string>;
}

// ─── reEncrypt ────────────────────────────────────────────────────────────────

export interface ReEncryptOptions {
  decryptFn?: (payload: string, purpose: string, options?: DecryptOptions) => Promise<string>;
  encryptFn?: (plaintext: string, purpose: string, options?: EncryptOptions) => Promise<string>;
  purpose: string;
  options?: EncryptOptions | DecryptOptions;
}

// ─── Key Export ───────────────────────────────────────────────────────────────

export type KeyExportFormat = 'hex' | 'base64' | 'base64url' | 'jwk';

// ─── Error codes (extended) ───────────────────────────────────────────────────
