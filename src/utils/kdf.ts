import { getCrypto, encode, hexToBytes } from './env.js';
import type { HashAlgorithm } from '../types/index.js';

/**
 * Derives a cryptographic key from a master key using HKDF (RFC 5869).
 * Uses the Web Crypto API so it works in Node 18+, browsers, and edge runtimes.
 *
 * @param masterKeyHex - 64-char hex string (32-byte master key)
 * @param purpose      - Domain-separation string (e.g. 'user:session')
 * @param namespace    - Package namespace (default: 'encryptix')
 * @param hash         - Hash algorithm for HKDF (default: 'sha-256')
 * @param length       - Output key length in bytes (default: 32)
 * @param salt         - Optional salt bytes; defaults to zero-filled
 */
export async function deriveKey(
  masterKeyHex: string,
  purpose: string,
  namespace = 'encryptix',
  hash: HashAlgorithm = 'sha256',
  length = 32,
  salt?: Uint8Array,
): Promise<CryptoKey> {
  const subtle = getCrypto().subtle;

  // Import the master key as raw HKDF key material
  const keyMaterial = await subtle.importKey(
    'raw',
    hexToBytes(masterKeyHex) as unknown as Uint8Array<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveKey'],
  );

  const info = encode(`${namespace}:${purpose}`);
  const effectiveSalt = salt ?? new Uint8Array(32); // zero-filled salt = no salt

  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: hash.toUpperCase().replace('SHA', 'SHA-') as AlgorithmIdentifier, // sha256 → SHA-256
      info: info as unknown as Uint8Array<ArrayBuffer>,
      salt: effectiveSalt as unknown as Uint8Array<ArrayBuffer>,
    },
    keyMaterial,
    { name: 'AES-GCM', length: length * 8 },
    false,           // not extractable — key never leaves the crypto layer
    ['encrypt', 'decrypt'],
  );
}

/**
 * Derives raw key bytes (not a CryptoKey) for use with algorithms
 * that need the raw material (e.g. ChaCha20 via Node's native crypto).
 */
export async function deriveRawKey(
  masterKeyHex: string,
  purpose: string,
  namespace = 'encryptix',
  hash: HashAlgorithm = 'sha256',
  length = 32,
  salt?: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;

  const keyMaterial = await subtle.importKey(
    'raw',
    hexToBytes(masterKeyHex) as unknown as Uint8Array<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveBits'],
  );

  const info = encode(`${namespace}:${purpose}`);
  const effectiveSalt = salt ?? new Uint8Array(32);

  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: hash.toUpperCase().replace('SHA', 'SHA-') as AlgorithmIdentifier,
      info: info as unknown as Uint8Array<ArrayBuffer>,
      salt: effectiveSalt as unknown as Uint8Array<ArrayBuffer>,
    },
    keyMaterial,
    length * 8,
  );

  return new Uint8Array(bits);
}
