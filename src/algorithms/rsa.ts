/**
 * RSA-OAEP asymmetric encryption using the Web Crypto API.
 * Works in Node 18+, modern browsers, and edge runtimes.
 *
 * Key size: 2048 or 4096 bits
 * Hash:     SHA-256 (default) or SHA-512
 *
 * Intended use: encrypt small payloads (e.g. symmetric keys, tokens).
 * For large data, encrypt with AES/ChaCha and use RSA to wrap the key.
 */

import { getCrypto, encode, decode, bytesToBase64, base64ToBytes, hexToBytes } from '../utils/env.js';
import { EncryptixError } from '../utils/errors.js';
import type { RSAKeyPair, Encoding } from '../types/index.js';

type RSAHashAlg = 'SHA-256' | 'SHA-512';

// ─── Key Generation ───────────────────────────────────────────────────────────

export async function generateRSAKeyPair(
  modulusLength: 2048 | 4096 = 2048,
  hash: RSAHashAlg = 'SHA-256',
): Promise<RSAKeyPair> {
  const subtle = getCrypto().subtle;

  let keyPair: CryptoKeyPair;
  try {
    keyPair = await subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash },
      true,
      ['encrypt', 'decrypt'],
    );
  } catch (err) {
    throw new EncryptixError('RSA_KEY_ERROR', 'Failed to generate RSA key pair.', err);
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

// ─── Encrypt ─────────────────────────────────────────────────────────────────

export async function rsaEncrypt(
  plaintext: string,
  publicKeyPEM: string,
  encoding: Encoding = 'base64',
  hash: RSAHashAlg = 'SHA-256',
): Promise<string> {
  const subtle = getCrypto().subtle;

  const publicKey = await importPublicKey(publicKeyPEM, hash);

  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encode(plaintext) as unknown as Uint8Array<ArrayBuffer>,
    );
  } catch (err) {
    throw new EncryptixError('ENCRYPTION_FAILED', 'RSA-OAEP encryption failed.', err);
  }

  const bytes = new Uint8Array(ciphertext);
  if (encoding === 'hex') return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  if (encoding === 'base64url') return bytesToBase64(bytes, true);
  return bytesToBase64(bytes, false);
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

export async function rsaDecrypt(
  ciphertext: string,
  privateKeyPEM: string,
  encoding: Encoding = 'base64',
  hash: RSAHashAlg = 'SHA-256',
): Promise<string> {
  const subtle = getCrypto().subtle;

  const privateKey = await importPrivateKey(privateKeyPEM, hash);

  const ciphertextBytes = encoding === 'hex'
    ? hexToBytes(ciphertext)
    : base64ToBytes(ciphertext);

  let plainBuffer: ArrayBuffer;
  try {
    plainBuffer = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, ciphertextBytes as unknown as Uint8Array<ArrayBuffer>);
  } catch (err) {
    throw new EncryptixError('DECRYPTION_FAILED', 'RSA-OAEP decryption failed. Wrong key or corrupted ciphertext.', err);
  }

  return decode(new Uint8Array(plainBuffer));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function importPublicKey(pem: string, hash: RSAHashAlg): Promise<CryptoKey> {
  try {
    const spki = fromPEM(pem);
    return await getCrypto().subtle.importKey(
      'spki', spki, { name: 'RSA-OAEP', hash }, false, ['encrypt'],
    );
  } catch (err) {
    throw new EncryptixError('RSA_KEY_ERROR', 'Failed to import RSA public key. Ensure it is a valid PEM-encoded SPKI key.', err);
  }
}

async function importPrivateKey(pem: string, hash: RSAHashAlg): Promise<CryptoKey> {
  try {
    const pkcs8 = fromPEM(pem);
    return await getCrypto().subtle.importKey(
      'pkcs8', pkcs8, { name: 'RSA-OAEP', hash }, false, ['decrypt'],
    );
  } catch (err) {
    throw new EncryptixError('RSA_KEY_ERROR', 'Failed to import RSA private key. Ensure it is a valid PEM-encoded PKCS8 key.', err);
  }
}

function toPEM(buffer: ArrayBuffer, label: string): string {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const wrapped = base64.match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

function fromPEM(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s+/g, '');
  return base64ToBytes(base64).buffer as ArrayBuffer;
}
