/**
 * ChaCha20-Poly1305 authenticated encryption.
 *
 * ChaCha20-Poly1305 is NOT available in the Web Crypto API (as of 2025),
 * so we use Node's native `crypto` module on Node runtimes.
 *
 * For browser/edge environments we throw a clear error; callers should
 * fall back to AES-256-GCM which is universally available.
 *
 * Payload binary layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x02 = chacha20-poly1305
 *   [12 bytes iv/nonce]
 *   [16 bytes tag    ]
 *   [N bytes ciphertext]
 */

import { encode, concatBytes, RUNTIME } from '../utils/env.js';
import { deriveRawKey } from '../utils/kdf.js';
import { EncryptixError } from '../utils/errors.js';
import type { HashAlgorithm } from '../types/index.js';

export const ALGO_ID = 0x02;
const IV_LENGTH = 12;   // ChaCha20 uses a 96-bit (12-byte) nonce
const TAG_LENGTH = 16;
const VERSION = 0x01;

function assertNodeRuntime(): void {
  if (RUNTIME !== 'node') {
    throw new EncryptixError(
      'ENVIRONMENT_UNSUPPORTED',
      'ChaCha20-Poly1305 is only available in Node.js environments. ' +
      'Use aes-256-gcm for browser and edge runtime compatibility.',
    );
  }
}

export async function chachaEncrypt(
  plaintext: string,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  assertNodeRuntime();

  const { createCipheriv, randomBytes } = await import('crypto');
  const rawKey = await deriveRawKey(masterKeyHex, purpose, namespace, hash);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv('chacha20-poly1305', rawKey, iv, {
    authTagLength: TAG_LENGTH,
  } as any);

  const purposeBytes = encode(purpose);
  const effectiveAAD = aad ? concatBytes(purposeBytes, aad) : purposeBytes;
  cipher.setAAD(effectiveAAD, {} as any);

  let encrypted: Buffer;
  try {
    encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  } catch (err) {
    throw new EncryptixError('ENCRYPTION_FAILED', 'ChaCha20-Poly1305 encryption failed.', err);
  }

  const tag = cipher.getAuthTag();

  return concatBytes(
    new Uint8Array([VERSION, ALGO_ID]),
    new Uint8Array(iv),
    new Uint8Array(tag),
    new Uint8Array(encrypted),
  );
}

export async function chachaDecrypt(
  data: Uint8Array,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<string> {
  assertNodeRuntime();

  const version = data[0];
  if (version !== VERSION) {
    throw new EncryptixError('UNSUPPORTED_VERSION', `Unsupported payload version: ${version}`);
  }
  const algoId = data[1];
  if (algoId !== ALGO_ID) {
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Payload algo_id ${algoId} is not ChaCha20-Poly1305 (0x02)`);
  }

  const iv = data.slice(2, 2 + IV_LENGTH);
  const tag = data.slice(2 + IV_LENGTH, 2 + IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.slice(2 + IV_LENGTH + TAG_LENGTH);

  const { createDecipheriv } = await import('crypto');
  const rawKey = await deriveRawKey(masterKeyHex, purpose, namespace, hash);

  const decipher = createDecipheriv('chacha20-poly1305', rawKey, iv, {
    authTagLength: TAG_LENGTH,
  } as any);

  const purposeBytes = encode(purpose);
  const effectiveAAD = aad ? concatBytes(purposeBytes, aad) : purposeBytes;
  decipher.setAAD(effectiveAAD, {} as any);
  decipher.setAuthTag(Buffer.from(tag));

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    throw new EncryptixError(
      'DECRYPTION_FAILED',
      'ChaCha20-Poly1305 decryption failed. The payload may be corrupt, tampered, or the wrong purpose/key was used.',
      err,
    );
  }
}
