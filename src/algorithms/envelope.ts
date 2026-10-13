/**
 * Envelope Encryption for @scriptixlabs/encryptix
 *
 * Pattern:
 *   1. Generate a random 256-bit Data Encryption Key (DEK) per payload
 *   2. Encrypt the actual data with the DEK (AES-256-GCM or ChaCha20)
 *   3. Wrap the DEK with the Key Encryption Key (KEK) using AES-KW (RFC 3394)
 *   4. Store: { wrappedDek, ciphertext, metadata }
 *
 * Benefits:
 *   - Revoking access to ONE record: re-wrap or discard its DEK
 *   - Rotating the KEK: re-wrap all DEKs without re-encrypting data
 *   - Multiple recipients: wrap the same DEK with each recipient's KEK
 *   - The KEK (your master key) never directly touches the data
 */

import { getCrypto, concatBytes, encode, bytesToBase64, base64ToBytes, bytesToHex, hexToBytes } from '../utils/env.js';
import { deriveRawKey } from '../utils/kdf.js';
import { aesEncrypt, aesDecrypt } from './aes-gcm.js';
import { chachaEncrypt, chachaDecrypt } from './chacha20.js';
import { EncryptixError } from '../utils/errors.js';
import { hash } from '../utils/tokens.js';
import type {
  EnvelopePayload,
  EnvelopeEncryptOptions,
  EnvelopeDecryptOptions,
  SymmetricAlgorithm,
  HashAlgorithm,
  Encoding,
} from '../types/index.js';

const ENVELOPE_VERSION = 1 as const;

// ─── Encrypt ─────────────────────────────────────────────────────────────────

export async function envelopeEncrypt(
  plaintext: string,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hashAlg: HashAlgorithm,
  options: EnvelopeEncryptOptions = {},
): Promise<EnvelopePayload> {
  const dataAlgorithm: SymmetricAlgorithm = options.dataAlgorithm ?? 'aes-256-gcm';
  const encoding: Encoding = options.encoding ?? 'base64';
  const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;

  // 1. Generate a fresh random DEK (32 bytes)
  const dek = getCrypto().getRandomValues(new Uint8Array(32));
  const dekHex = bytesToHex(dek);

  // 2. Encrypt the plaintext with the DEK
  //    Derive a KEK from the master key for AES-KW wrapping (separate purpose)
  let dataCiphertext: Uint8Array;
  if (dataAlgorithm === 'aes-256-gcm') {
    dataCiphertext = await aesEncrypt(plaintext, dekHex, `${purpose}:dek-data`, namespace, hashAlg, aad);
  } else {
    dataCiphertext = await chachaEncrypt(plaintext, dekHex, `${purpose}:dek-data`, namespace, hashAlg, aad);
  }

  // 3. Derive the KEK from master key (scoped to wrapping purpose)
  const kekRaw = await deriveRawKey(masterKeyHex, `${purpose}:kek-wrap`, namespace, hashAlg, 32);

  // 4. Wrap DEK with AES-KW (RFC 3394) using the KEK
  const subtle = getCrypto().subtle;
  const kekCryptoKey = await subtle.importKey('raw', kekRaw as unknown as Uint8Array<ArrayBuffer>, 'AES-KW', false, ['wrapKey']);
  const dekCryptoKey = await subtle.importKey('raw', dek, 'AES-GCM', true, ['encrypt', 'decrypt']);

  let wrappedDekBuffer: ArrayBuffer;
  try {
    wrappedDekBuffer = await subtle.wrapKey('raw', dekCryptoKey, kekCryptoKey, 'AES-KW');
  } catch (err) {
    throw new EncryptixError('ENVELOPE_ERROR', 'Failed to wrap DEK with KEK.', err);
  }

  // 5. Compute KEK fingerprint (first 8 bytes of SHA-256(kekRaw)) for key identification
  const kekFingerprint = (await hash(kekRaw, 'sha256', 'hex')).slice(0, 16);

  const encodeBytes = (b: Uint8Array) =>
    encoding === 'hex'
      ? bytesToHex(b)
      : bytesToBase64(b, encoding === 'base64url');

  return {
    wrappedDek: encodeBytes(new Uint8Array(wrappedDekBuffer)),
    ciphertext: encodeBytes(dataCiphertext),
    wrapAlgorithm: 'AES-KW',
    dataAlgorithm,
    kekFingerprint,
    version: ENVELOPE_VERSION,
  };
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

export async function envelopeDecrypt(
  envelope: EnvelopePayload,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hashAlg: HashAlgorithm,
  options: EnvelopeDecryptOptions = {},
): Promise<string> {
  if (envelope.version !== ENVELOPE_VERSION) {
    throw new EncryptixError('UNSUPPORTED_VERSION', `Unsupported envelope version: ${envelope.version}`);
  }
  if (envelope.wrapAlgorithm !== 'AES-KW') {
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unsupported wrap algorithm: ${envelope.wrapAlgorithm}`);
  }

  const encoding: Encoding = options.encoding ?? 'base64';
  const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;

  const decodeStr = (s: string) =>
    encoding === 'hex'
      ? hexToBytes(s)
      : base64ToBytes(s);

  // 1. Derive the KEK from master key
  const kekRaw = await deriveRawKey(masterKeyHex, `${purpose}:kek-wrap`, namespace, hashAlg, 32);

  // 2. Unwrap the DEK
  const subtle = getCrypto().subtle;
  const kekCryptoKey = await subtle.importKey('raw', kekRaw as unknown as Uint8Array<ArrayBuffer>, 'AES-KW', false, ['unwrapKey']);
  const wrappedDekBytes = decodeStr(envelope.wrappedDek);

  let dekCryptoKey: CryptoKey;
  try {
    dekCryptoKey = await subtle.unwrapKey(
      'raw',
      wrappedDekBytes as unknown as Uint8Array<ArrayBuffer>,
      kekCryptoKey,
      'AES-KW',
      'AES-GCM',
      true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    throw new EncryptixError(
      'ENVELOPE_ERROR',
      'Failed to unwrap DEK. Wrong key or corrupted envelope.',
      err,
    );
  }

  // 3. Export DEK as hex for use with existing decrypt functions
  const dekRaw = await subtle.exportKey('raw', dekCryptoKey);
  const dekHex = bytesToHex(new Uint8Array(dekRaw));

  // 4. Decrypt the data with the DEK
  const ciphertextBytes = decodeStr(envelope.ciphertext);

  if (envelope.dataAlgorithm === 'aes-256-gcm') {
    return aesDecrypt(ciphertextBytes, dekHex, `${purpose}:dek-data`, namespace, hashAlg, aad);
  } else if (envelope.dataAlgorithm === 'chacha20-poly1305') {
    return chachaDecrypt(ciphertextBytes, dekHex, `${purpose}:dek-data`, namespace, hashAlg, aad);
  } else {
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Unsupported data algorithm: ${envelope.dataAlgorithm}`);
  }
}
