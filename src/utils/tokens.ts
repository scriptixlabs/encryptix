/**
 * Hashing, HMAC signing, and secure token generation utilities.
 * All functions use the Web Crypto API where possible for cross-runtime compatibility.
 */

import {
  getCrypto, encode, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
  encodeOutput, decodeInput, timingSafeEqual,
} from './env.js';
import { EncryptixError } from './errors.js';
import type {
  HashAlgorithm, HmacKey, HmacKeyEncoding, HmacOptions, HmacOutputEncoding,
} from '../types/index.js';

// ─── Hashing ─────────────────────────────────────────────────────────────────

/**
 * SHA-256 / SHA-384 / SHA-512 hash of a string or bytes.
 * Constant across all runtimes via Web Crypto.
 */
export async function hash(
  input: string | Uint8Array,
  algorithm: HashAlgorithm = 'sha256',
  encoding: 'hex' | 'base64' | 'base64url' = 'hex',
): Promise<string> {
  const data = typeof input === 'string' ? encode(input) : input;
  const webAlgo = toWebHashAlgo(algorithm);

  let digest: ArrayBuffer;
  try {
    digest = await getCrypto().subtle.digest(webAlgo, data as unknown as Uint8Array<ArrayBuffer>);
  } catch (err) {
    throw new EncryptixError('ENCRYPTION_FAILED', `Hashing with ${algorithm} failed.`, err);
  }

  const bytes = new Uint8Array(digest);
  if (encoding === 'base64') return bytesToBase64(bytes);
  if (encoding === 'base64url') return bytesToBase64(bytes, true);
  return bytesToHex(bytes);
}

// ─── HMAC ─────────────────────────────────────────────────────────────────────

/**
 * Normalises the trailing HMAC arguments. Accepts either the 1.0.0 positional
 * form `(algorithm?, encoding?)` or a single `HmacOptions` object.
 * @internal
 */
export function resolveHmacOptions(
  algorithmOrOptions?: HashAlgorithm | HmacOptions,
  encoding?: HmacOutputEncoding,
): Required<HmacOptions> {
  const opts: HmacOptions =
    typeof algorithmOrOptions === 'object' && algorithmOrOptions !== null
      ? algorithmOrOptions
      : { algorithm: algorithmOrOptions, encoding };
  return {
    algorithm: opts.algorithm ?? 'sha256',
    encoding: opts.encoding ?? 'hex',
    keyEncoding: opts.keyEncoding ?? 'hex',
  };
}

/**
 * Converts an HMAC key to raw bytes. Throws `INVALID_KEY` for a missing/empty
 * key or a string that is not valid in the declared `keyEncoding`.
 */
function hmacKeyBytes(key: HmacKey, keyEncoding: HmacKeyEncoding): Uint8Array {
  if (key instanceof Uint8Array) {
    if (key.length === 0) throw new EncryptixError('INVALID_KEY', 'HMAC key must not be empty.');
    return key;
  }
  if (typeof key !== 'string' || key.length === 0) {
    throw new EncryptixError('INVALID_KEY', 'HMAC key must be a non-empty string or Uint8Array.');
  }
  try {
    switch (keyEncoding) {
      case 'utf8': return encode(key);
      case 'hex': return hexToBytes(key);
      case 'base64':
      case 'base64url': return base64ToBytes(key);
      default:
        throw new EncryptixError('INVALID_KEY', `Unsupported HMAC keyEncoding: ${String(keyEncoding)}.`);
    }
  } catch (err) {
    if (err instanceof EncryptixError && err.code === 'INVALID_KEY') throw err;
    const hint = keyEncoding === 'hex'
      ? " If this is a plain-text secret (e.g. a webhook secret), pass { keyEncoding: 'utf8' }."
      : '';
    throw new EncryptixError('INVALID_KEY', `HMAC key is not valid ${keyEncoding}.${hint}`, err);
  }
}

async function hmacBytes(
  message: string | Uint8Array,
  key: HmacKey,
  opts: Required<HmacOptions>,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const webAlgo = toWebHashAlgo(opts.algorithm);
  const keyBytes = hmacKeyBytes(key, opts.keyEncoding);

  let signature: ArrayBuffer;
  try {
    const cryptoKey = await subtle.importKey(
      'raw',
      keyBytes as unknown as Uint8Array<ArrayBuffer>,
      { name: 'HMAC', hash: webAlgo },
      false,
      ['sign'],
    );
    const data = typeof message === 'string' ? encode(message) : message;
    signature = await subtle.sign('HMAC', cryptoKey, data as unknown as Uint8Array<ArrayBuffer>);
  } catch (err) {
    throw new EncryptixError('ENCRYPTION_FAILED', 'HMAC signing failed.', err);
  }
  return new Uint8Array(signature);
}

/**
 * Produces an HMAC signature for a message.
 *
 * The key is either raw bytes (`Uint8Array`) or a string decoded according to
 * `keyEncoding` — **hex by default**, for compatibility with 1.0.0. Plain-text
 * secrets must opt in with `{ keyEncoding: 'utf8' }`; a non-hex string with the
 * default encoding throws `INVALID_KEY` rather than being silently mangled.
 *
 * @example
 * // 1.0.0 positional form (hex key) — unchanged
 * await hmac(body, keyHex, 'sha256', 'hex');
 *
 * // Shopify webhook: plain-text secret, base64 digest
 * await hmac(rawBody, process.env.SHOPIFY_SECRET!, { keyEncoding: 'utf8', encoding: 'base64' });
 */
export async function hmac(
  message: string | Uint8Array,
  key: HmacKey,
  algorithm?: HashAlgorithm,
  encoding?: HmacOutputEncoding,
): Promise<string>;
export async function hmac(
  message: string | Uint8Array,
  key: HmacKey,
  options?: HmacOptions,
): Promise<string>;
export async function hmac(
  message: string | Uint8Array,
  key: HmacKey,
  algorithmOrOptions?: HashAlgorithm | HmacOptions,
  encoding?: HmacOutputEncoding,
): Promise<string> {
  const opts = resolveHmacOptions(algorithmOrOptions, encoding);
  const bytes = await hmacBytes(message, key, opts);
  return encodeOutput(bytes, opts.encoding);
}

/**
 * Verifies an HMAC signature in constant time.
 *
 * The provided `signature` is decoded using `encoding` (hex is
 * case-insensitive; base64 padding is optional) and compared as bytes with
 * `timingSafeEqual` (Node's native implementation where available). Returns
 * false for a wrong signature, a length mismatch, or a signature that is not
 * valid in the declared encoding. Key problems still throw `INVALID_KEY`.
 *
 * @example
 * // Shopify: X-Shopify-Hmac-Sha256 is base64 of HMAC-SHA256(rawBody, secret)
 * await verifyHmac(rawBody, secret, header, { keyEncoding: 'utf8', encoding: 'base64' });
 */
export async function verifyHmac(
  message: string | Uint8Array,
  key: HmacKey,
  signature: string,
  algorithm?: HashAlgorithm,
  encoding?: HmacOutputEncoding,
): Promise<boolean>;
export async function verifyHmac(
  message: string | Uint8Array,
  key: HmacKey,
  signature: string,
  options?: HmacOptions,
): Promise<boolean>;
export async function verifyHmac(
  message: string | Uint8Array,
  key: HmacKey,
  signature: string,
  algorithmOrOptions?: HashAlgorithm | HmacOptions,
  encoding?: HmacOutputEncoding,
): Promise<boolean> {
  const opts = resolveHmacOptions(algorithmOrOptions, encoding);
  const expected = await hmacBytes(message, key, opts);

  if (typeof signature !== 'string' || signature.length === 0) return false;
  let provided: Uint8Array;
  try {
    provided = decodeInput(signature, opts.encoding);
  } catch {
    return false;
  }
  return timingSafeEqual(expected, provided);
}

// ─── Token Generation ─────────────────────────────────────────────────────────

/**
 * Generates a cryptographically random token.
 * @param bytes  - Number of random bytes (default: 32 → 64-char hex)
 * @param encoding - Output format
 */
export function generateToken(bytes = 32, encoding: 'hex' | 'base64' | 'base64url' = 'hex'): string {
  const arr = getCrypto().getRandomValues(new Uint8Array(bytes));
  if (encoding === 'base64') return bytesToBase64(arr);
  if (encoding === 'base64url') return bytesToBase64(arr, true);
  return bytesToHex(arr);
}

/**
 * Generates a secure random API key in the format `{prefix}_{base64url_random}`.
 * @example generateApiKey('sk') → 'sk_4xG9...'
 */
export function generateApiKey(prefix = 'key', bytes = 32): string {
  const token = generateToken(bytes, 'base64url');
  return `${prefix}_${token}`;
}

/**
 * Generates a UUID v4 using the platform's crypto.randomUUID if available,
 * falling back to manual construction.
 */
export function generateUUID(): string {
  if (typeof getCrypto().randomUUID === 'function') {
    return getCrypto().randomUUID!();
  }
  // Manual fallback
  const bytes = getCrypto().getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant bits
  const hex = bytesToHex(bytes);
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function toWebHashAlgo(alg: HashAlgorithm): string {
  return alg.toUpperCase().replace('SHA', 'SHA-'); // sha256 → SHA-256
}
