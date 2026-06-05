/**
 * AES-256-GCM authenticated encryption using the Web Crypto API.
 * Works identically in Node 18+, browsers, and edge runtimes.
 *
 * Payload binary layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x01 = aes-256-gcm
 *   [12 bytes iv     ]
 *   [16 bytes tag    ]
 *   [N bytes ciphertext]
 */

import { getCrypto, concatBytes, encode } from '../utils/env.js';
import { deriveKey } from '../utils/kdf.js';
import { EncryptixError } from '../utils/errors.js';
import type { HashAlgorithm } from '../types/index.js';

export const ALGO_ID = 0x01;
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
const VERSION = 0x01;

export async function aesEncrypt(
  plaintext: string,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const key = await deriveKey(masterKeyHex, purpose, namespace, hash);

  const iv = getCrypto().getRandomValues(new Uint8Array(IV_LENGTH));

  // Build AAD = purpose + optional extra aad
  const purposeBytes = encode(purpose);
  const effectiveAAD = aad ? concatBytes(purposeBytes, aad) : purposeBytes;

  let ciphertextWithTag: ArrayBuffer;
  try {
    ciphertextWithTag = await subtle.encrypt(
      { name: 'AES-GCM', iv: iv as unknown as Uint8Array<ArrayBuffer>, additionalData: effectiveAAD as unknown as Uint8Array<ArrayBuffer>, tagLength: TAG_LENGTH * 8 },
      key,
      encode(plaintext) as unknown as Uint8Array<ArrayBuffer>,
    );
  } catch (err) {
    throw new EncryptixError('ENCRYPTION_FAILED', 'AES-256-GCM encryption failed.', err);
  }

  // Web Crypto appends the auth tag at the END of the ciphertext buffer
  const full = new Uint8Array(ciphertextWithTag);
  const ciphertext = full.slice(0, full.length - TAG_LENGTH);
  const tag = full.slice(full.length - TAG_LENGTH);

  return concatBytes(
    new Uint8Array([VERSION, ALGO_ID]),
    iv,
    tag,
    ciphertext,
  );
}

export async function aesDecrypt(
  data: Uint8Array,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<string> {
  const subtle = getCrypto().subtle;

  const version = data[0];
  if (version !== VERSION) {
    throw new EncryptixError('UNSUPPORTED_VERSION', `Unsupported payload version: ${version}`);
  }
  const algoId = data[1];
  if (algoId !== ALGO_ID) {
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Payload algo_id ${algoId} is not AES-256-GCM (0x01)`);
  }

  const iv = data.slice(2, 2 + IV_LENGTH);
  const tag = data.slice(2 + IV_LENGTH, 2 + IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.slice(2 + IV_LENGTH + TAG_LENGTH);

  const key = await deriveKey(masterKeyHex, purpose, namespace, hash);

  const purposeBytes = encode(purpose);
  const effectiveAAD = aad ? concatBytes(purposeBytes, aad) : purposeBytes;

  // Re-assemble ciphertext + tag for Web Crypto
  const ciphertextWithTag = concatBytes(ciphertext, tag);

  let plainBuffer: ArrayBuffer;
  try {
    plainBuffer = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as Uint8Array<ArrayBuffer>, additionalData: effectiveAAD as unknown as Uint8Array<ArrayBuffer>, tagLength: TAG_LENGTH * 8 },
      key,
      ciphertextWithTag as unknown as Uint8Array<ArrayBuffer>,
    );
  } catch (err) {
    throw new EncryptixError(
      'DECRYPTION_FAILED',
      'AES-256-GCM decryption failed. The payload may be corrupt, tampered, or the wrong purpose/key was used.',
      err,
    );
  }

  return new TextDecoder().decode(plainBuffer);
}
