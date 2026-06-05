/**
 * AES-SIV (Synthetic IV) — Deterministic Authenticated Encryption
 *
 * RFC 5297: https://tools.ietf.org/html/rfc5297
 *
 * AES-SIV encrypts the same plaintext to the same ciphertext given the same
 * key and AAD. This enables:
 *   - Searching over encrypted data (encrypted email lookup, encrypted index)
 *   - Deduplication of encrypted values
 *   - Deterministic token generation
 *
 * ⚠️ IMPORTANT SECURITY NOTES:
 *   1. Nonce-reuse resistant but NOT nonce-reuse immune — if you encrypt the
 *      same plaintext twice you get the same ciphertext, which leaks equality.
 *      This is by design and is the point. Only use when equality-leakage is acceptable.
 *   2. Do NOT use for data that requires hiding whether two values are equal.
 *      Use regular AES-GCM encrypt() for that.
 *   3. Binding AAD to the ciphertext is critical for domain separation.
 *      Always pass a meaningful `purpose` (which we do via HKDF).
 *
 * Implementation:
 *   AES-SIV uses two AES keys:
 *     K1 — for S2V (CMAC-based synthetic IV generation)
 *     K2 — for AES-CTR encryption
 *
 *   We implement CMAC via AES-CBC (available in Web Crypto):
 *     CMAC(K, M) = AES-CBC-MAC with subkey derivation per NIST SP 800-38B
 *
 * Layout (after base64 decode):
 *   [1 byte  version ]
 *   [1 byte  algo_id ] — 0x03 = aes-siv
 *   [16 bytes SIV/tag ]
 *   [N bytes ciphertext]
 */

import { getCrypto, concatBytes, encode } from '../utils/env.js';
import { deriveRawKey } from '../utils/kdf.js';
import { EncryptixError } from '../utils/errors.js';
import type { HashAlgorithm } from '../types/index.js';

export const ALGO_ID = 0x03;
const SIV_LENGTH = 16;
const VERSION = 0x01;

// ─── Encrypt ─────────────────────────────────────────────────────────────────

export async function sivEncrypt(
  plaintext: string,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  // Derive 64 bytes: first 32 = K1 (S2V key), last 32 = K2 (CTR key)
  const keyMaterial = await deriveRawKey(masterKeyHex, `${purpose}:siv`, namespace, hash, 64);
  const k1 = keyMaterial.slice(0, 32);
  const k2 = keyMaterial.slice(32, 64);

  const plaintextBytes = encode(plaintext);
  const purposeBytes = encode(purpose);
  const components = aad ? [purposeBytes, aad] : [purposeBytes];

  // Compute SIV = S2V(K1, components..., plaintext)
  const siv = await s2v(k1, components, plaintextBytes);

  // Encrypt with AES-CTR, using SIV as the counter (with top 2 bits cleared per RFC 5297)
  const ctrIv = new Uint8Array(siv);
  ctrIv[8] &= 0x7f; // clear bit 63
  ctrIv[12] &= 0x7f; // clear bit 31

  const ciphertext = await aesCtrEncrypt(k2, ctrIv, plaintextBytes);

  return concatBytes(
    new Uint8Array([VERSION, ALGO_ID]),
    siv,
    ciphertext,
  );
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

export async function sivDecrypt(
  data: Uint8Array,
  masterKeyHex: string,
  purpose: string,
  namespace: string,
  hash: HashAlgorithm,
  aad?: Uint8Array,
): Promise<string> {
  const version = data[0];
  if (version !== VERSION) {
    throw new EncryptixError('UNSUPPORTED_VERSION', `Unsupported payload version: ${version}`);
  }
  const algoId = data[1];
  if (algoId !== ALGO_ID) {
    throw new EncryptixError('UNSUPPORTED_ALGORITHM', `Payload algo_id ${algoId} is not AES-SIV (0x03)`);
  }

  const siv = data.slice(2, 2 + SIV_LENGTH);
  const ciphertext = data.slice(2 + SIV_LENGTH);

  const keyMaterial = await deriveRawKey(masterKeyHex, `${purpose}:siv`, namespace, hash, 64);
  const k1 = keyMaterial.slice(0, 32);
  const k2 = keyMaterial.slice(32, 64);

  // Decrypt with AES-CTR (same as encrypt — CTR is symmetric)
  const ctrIv = new Uint8Array(siv);
  ctrIv[8] &= 0x7f;
  ctrIv[12] &= 0x7f;

  const plaintext = await aesCtrEncrypt(k2, ctrIv, ciphertext);

  // Verify authenticity: recompute S2V and compare with stored SIV
  const purposeBytes = encode(purpose);
  const components = aad ? [purposeBytes, aad] : [purposeBytes];
  const expectedSiv = await s2v(k1, components, plaintext);

  if (!constantTimeEqual(siv, expectedSiv)) {
    throw new EncryptixError(
      'DECRYPTION_FAILED',
      'AES-SIV authentication failed. Payload is tampered, corrupt, or wrong purpose/AAD was used.',
    );
  }

  return new TextDecoder().decode(plaintext);
}

// ─── S2V (Synthetic IV Generation per RFC 5297) ───────────────────────────────

/**
 * S2V algorithm — computes a synthetic IV from multiple input components.
 * Uses AES-CMAC (implemented via AES-CBC with subkey derivation).
 */
async function s2v(
  key: Uint8Array,
  components: Uint8Array[],
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  // D = AES-CMAC(K, 0^128)
  let D = await cmac(key, new Uint8Array(16));

  // For each component: D = dbl(D) xor AES-CMAC(K, Si)
  for (const component of components) {
    D = xor16(dbl(D), await cmac(key, component));
  }

  // Final: if |plaintext| >= 128 bits: D = D xorend plaintext, then CMAC
  //        else: D = dbl(D) xor (plaintext || 10^*)
  let T: Uint8Array;
  if (plaintext.length >= 16) {
    T = xorEnd(plaintext, D);
  } else {
    T = xor16(dbl(D), pad(plaintext));
  }

  return cmac(key, T);
}

// ─── AES-CMAC (NIST SP 800-38B) via AES-CBC ──────────────────────────────────

async function cmac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const cryptoKey = await subtle.importKey('raw', key as unknown as Uint8Array<ArrayBuffer>, 'AES-CBC', false, ['encrypt']);

  // Generate subkeys K1, K2
  const zeroBlock = new Uint8Array(16);
  const L = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: zeroBlock }, cryptoKey, zeroBlock));
  // AES-CBC with zero IV on a zero block gives us E_K(0) in the first 16 bytes
  const Lblock = L.slice(0, 16);
  const K1 = generateSubkey(Lblock);
  const K2 = generateSubkey(K1);

  // Pad/process message
  const n = Math.ceil(message.length / 16);
  const flag = message.length > 0 && message.length % 16 === 0;
  const lastBlock = flag
    ? xor16(message.slice((n - 1) * 16), K1)
    : xor16(cmacPad(message.slice((n - 1) * 16)), K2);

  // CBC-MAC over all blocks
  let X = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) {
    const block = message.slice(i * 16, (i + 1) * 16);
    const enc = new Uint8Array(await subtle.encrypt(
      { name: 'AES-CBC', iv: X as unknown as Uint8Array<ArrayBuffer> },
      cryptoKey,
      block as unknown as Uint8Array<ArrayBuffer>,
    ));
    X = enc.slice(0, 16);
  }

  const finalEnc = new Uint8Array(await subtle.encrypt(
    { name: 'AES-CBC', iv: X as unknown as Uint8Array<ArrayBuffer> },
    cryptoKey,
    lastBlock as unknown as Uint8Array<ArrayBuffer>,
  ));

  return finalEnc.slice(0, 16);
}

function generateSubkey(L: Uint8Array): Uint8Array {
  const msb = (L[0] & 0x80) !== 0;
  const shifted = new Uint8Array(16);
  for (let i = 0; i < 15; i++) {
    shifted[i] = ((L[i] << 1) | (L[i + 1] >> 7)) & 0xff;
  }
  shifted[15] = (L[15] << 1) & 0xff;
  if (msb) shifted[15] ^= 0x87; // Rb constant for AES (128-bit)
  return shifted;
}

function cmacPad(block: Uint8Array): Uint8Array {
  const padded = new Uint8Array(16);
  padded.set(block);
  padded[block.length] = 0x80;
  return padded;
}

// ─── AES-CTR ─────────────────────────────────────────────────────────────────

async function aesCtrEncrypt(key: Uint8Array, counter: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const subtle = getCrypto().subtle;
  const cryptoKey = await subtle.importKey('raw', key as unknown as Uint8Array<ArrayBuffer>, 'AES-CTR', false, ['encrypt']);
  const result = await subtle.encrypt(
    { name: 'AES-CTR', counter: counter as unknown as Uint8Array<ArrayBuffer>, length: 64 },
    cryptoKey,
    data as unknown as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(result);
}

// ─── Bit operations ───────────────────────────────────────────────────────────

/** Double a 128-bit value in GF(2^128) */
function dbl(b: Uint8Array): Uint8Array {
  const result = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    result[i] = ((b[i] << 1) | carry) & 0xff;
    carry = b[i] >> 7;
  }
  if (carry) result[15] ^= 0x87;
  return result;
}

/** XOR two 16-byte arrays */
function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) result[i] = a[i] ^ b[i];
  return result;
}

/** XOR the last 16 bytes of `data` with `mask` */
function xorEnd(data: Uint8Array, mask: Uint8Array): Uint8Array {
  const result = new Uint8Array(data);
  const offset = data.length - 16;
  for (let i = 0; i < 16; i++) result[offset + i] ^= mask[i];
  return result;
}

/** ISO/IEC 7816-4 padding to 16-byte boundary */
function pad(b: Uint8Array): Uint8Array {
  const padded = new Uint8Array(16);
  padded.set(b);
  padded[b.length] = 0x80;
  return padded;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
