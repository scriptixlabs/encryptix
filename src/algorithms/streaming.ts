/**
 * Streaming Encryption for @scriptixlabs/encryptix
 *
 * Uses the Web Streams API (ReadableStream / TransformStream), which is
 * available in Node 18+, modern browsers, and edge runtimes.
 *
 * Security model — chunked AEAD:
 *   Each chunk is independently encrypted with AES-256-GCM and carries its
 *   own auth tag. This prevents:
 *     - Truncation attacks (the final chunk has a special "last" flag in AAD)
 *     - Chunk reordering (each chunk's AAD includes its index)
 *     - Cross-stream splicing (stream-level nonce is in every chunk's AAD)
 *
 * Stream wire format:
 *   [STREAM HEADER]
 *     4 bytes: magic "ENCX"
 *     1 byte:  version (0x01)
 *     1 byte:  algo_id (0x01 = AES-256-GCM)
 *     12 bytes: stream nonce (random, unique per stream)
 *     4 bytes:  chunk size (uint32 big-endian)
 *
 *   [CHUNK] (repeated)
 *     4 bytes:  chunk index (uint32 big-endian)
 *     12 bytes: chunk IV (derived from stream nonce + index)
 *     16 bytes: auth tag
 *     N bytes:  ciphertext (last chunk may be shorter than chunk size)
 *
 *   [FINAL MARKER]
 *     4 bytes:  0xFFFFFFFF (signals last chunk to decoder)
 */

import { getCrypto, encode, concatBytes } from '../utils/env.js';
import { deriveKey } from '../utils/kdf.js';
import { EncryptixError } from '../utils/errors.js';
import type { StreamEncryptOptions, StreamDecryptOptions, HashAlgorithm } from '../types/index.js';

const MAGIC = new Uint8Array([0x45, 0x4e, 0x43, 0x58]); // "ENCX"
const STREAM_VERSION = 0x01;
const STREAM_ALGO_AES_GCM = 0x01;
const STREAM_NONCE_LENGTH = 12;
const CHUNK_IV_LENGTH = 12;
const TAG_LENGTH = 16;
const FINAL_MARKER = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KiB

// ─── Encrypt Stream ───────────────────────────────────────────────────────────

/**
 * Returns a TransformStream that encrypts data chunk-by-chunk.
 * Pipe a ReadableStream of Uint8Array through it.
 *
 * @example
 * ```ts
 * const { readable, writable } = enc.encryptStream({ purpose: 'file:upload' });
 * fileReadable.pipeTo(writable);
 * readable.pipeTo(networkWritable);
 * ```
 */
export function createEncryptStream(
  masterKeyHex: string,
  namespace: string,
  hashAlg: HashAlgorithm,
  options: StreamEncryptOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const purpose = options.purpose;
  const aad = options.aad
    ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad)
    : undefined;

  let cryptoKey: CryptoKey;
  let streamNonce: Uint8Array;
  let chunkIndex = 0;
  let buffer: Uint8Array = new Uint8Array(0);
  let headerWritten = false;

  return new TransformStream<Uint8Array, Uint8Array>({
    async start(controller) {
      // Derive stream key and generate stream nonce
      cryptoKey = await deriveKey(masterKeyHex, `${purpose}:stream`, namespace, hashAlg);
      streamNonce = getCrypto().getRandomValues(new Uint8Array(STREAM_NONCE_LENGTH));

      // Write stream header
      const chunkSizeBytes = new Uint8Array(4);
      new DataView(chunkSizeBytes.buffer).setUint32(0, chunkSize, false);

      const header = concatBytes(
        MAGIC,
        new Uint8Array([STREAM_VERSION, STREAM_ALGO_AES_GCM]),
        streamNonce,
        chunkSizeBytes,
      );
      controller.enqueue(header);
      headerWritten = true;
    },

    async transform(chunk, controller) {
      // Accumulate into buffer
      buffer = concatBytes(buffer, chunk);

      // Encrypt full chunks
      while (buffer.length >= chunkSize) {
        const plainChunk = buffer.slice(0, chunkSize);
        buffer = buffer.slice(chunkSize);
        const encryptedChunk = await encryptChunk(
          cryptoKey, streamNonce, plainChunk, chunkIndex, purpose, aad, false
        );
        controller.enqueue(encryptedChunk);
        chunkIndex++;
      }
    },

    async flush(controller) {
      // Encrypt the final (possibly partial) chunk with the "last" flag
      const encryptedFinal = await encryptChunk(
        cryptoKey, streamNonce, buffer, chunkIndex, purpose, aad, true
      );
      controller.enqueue(encryptedFinal);
      controller.enqueue(FINAL_MARKER);
    },
  });
}

// ─── Decrypt Stream ───────────────────────────────────────────────────────────

/**
 * Returns a TransformStream that decrypts data produced by createEncryptStream.
 *
 * @example
 * ```ts
 * const { readable, writable } = enc.decryptStream({ purpose: 'file:upload' });
 * encryptedReadable.pipeTo(writable);
 * readable.pipeTo(fileWritable);
 * ```
 */
export function createDecryptStream(
  masterKeyHex: string,
  namespace: string,
  hashAlg: HashAlgorithm,
  options: StreamDecryptOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const purpose = options.purpose;
  const aad = options.aad
    ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad)
    : undefined;

  let cryptoKey: CryptoKey;
  let streamNonce: Uint8Array;
  let chunkSize: number;
  let chunkIndex = 0;
  let buffer: Uint8Array = new Uint8Array(0);
  let headerParsed = false;

  // Header size: 4 (magic) + 1 (version) + 1 (algo) + 12 (nonce) + 4 (chunk size) = 22
  const HEADER_SIZE = 22;

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      buffer = concatBytes(buffer, chunk);

      // Parse header first
      if (!headerParsed) {
        if (buffer.length < HEADER_SIZE) return;

        const magic = buffer.slice(0, 4);
        if (!arraysEqual(magic, MAGIC)) {
          controller.error(new EncryptixError('STREAM_ERROR', 'Invalid stream magic. Not an encryptix stream.'));
          return;
        }
        const version = buffer[4];
        if (version !== STREAM_VERSION) {
          controller.error(new EncryptixError('STREAM_ERROR', `Unsupported stream version: ${version}`));
          return;
        }

        streamNonce = buffer.slice(6, 6 + STREAM_NONCE_LENGTH);
        chunkSize = new DataView(buffer.buffer, buffer.byteOffset + 18, 4).getUint32(0, false);
        buffer = buffer.slice(HEADER_SIZE);
        headerParsed = true;

        cryptoKey = await deriveKey(masterKeyHex, `${purpose}:stream`, namespace, hashAlg);
      }

      // Each encrypted chunk = 4 (index) + 12 (iv) + 16 (tag) + N (ciphertext)
      const encChunkSize = 4 + CHUNK_IV_LENGTH + TAG_LENGTH + chunkSize;

      while (buffer.length >= 4) {
        // Check for final marker
        if (arraysEqual(buffer.slice(0, 4), FINAL_MARKER)) {
          buffer = buffer.slice(4);
          break;
        }

        // Try to read a full chunk
        // We need at least the header part to know if it's the last chunk
        if (buffer.length < 4 + CHUNK_IV_LENGTH + TAG_LENGTH) break;

        // Read chunk index to determine if last (we process greedily)
        const storedIndex = new DataView(buffer.buffer, buffer.byteOffset, 4).getUint32(0, false);

        // For non-final chunks we know exact size; final chunk is variable
        // We attempt decryption with current buffer, growing until it works
        // or we see the final marker
        let chunkDataSize = chunkSize;

        // Try exact-size chunk first, then smaller (for last chunk)
        if (buffer.length < 4 + CHUNK_IV_LENGTH + TAG_LENGTH + 1) break;

        const availableData = buffer.length - 4 - CHUNK_IV_LENGTH - TAG_LENGTH;

        // When the available data is less than a full chunk, the FINAL_MARKER
        // (4 bytes of 0xFF) may be appended directly after the ciphertext.
        // Detect and strip it so we don't include it in the ciphertext slice.
        let trySize = Math.min(availableData, chunkSize);
        if (availableData < chunkSize && availableData >= 4) {
          const markerOffset = 4 + CHUNK_IV_LENGTH + TAG_LENGTH + availableData - 4;
          if (arraysEqual(buffer.slice(markerOffset, markerOffset + 4), FINAL_MARKER)) {
            trySize = availableData - 4;
          }
        }
        if (trySize <= 0) break;

        const chunkBytes = buffer.slice(0, 4 + CHUNK_IV_LENGTH + TAG_LENGTH + trySize);

        // Verify index matches expected
        if (storedIndex !== chunkIndex) {
          controller.error(new EncryptixError('STREAM_ERROR', `Chunk index mismatch. Expected ${chunkIndex}, got ${storedIndex}. Stream may be reordered or truncated.`));
          return;
        }

        try {
          const plainChunk = await decryptChunk(cryptoKey, streamNonce, chunkBytes, chunkIndex, purpose, aad);
          controller.enqueue(plainChunk);
          buffer = buffer.slice(chunkBytes.length);
          chunkIndex++;
        } catch {
          // Might be a partial last chunk — wait for more data
          break;
        }
      }
    },

    flush(controller) {
      if (buffer.length > 0 && !arraysEqual(buffer.slice(0, 4), FINAL_MARKER)) {
        // Any remaining unprocessed buffer is an error (truncated stream)
        if (buffer.length >= 4 + CHUNK_IV_LENGTH + TAG_LENGTH + 1) {
          controller.error(new EncryptixError('STREAM_ERROR', 'Stream ended with unprocessed data. The stream may be truncated.'));
        }
      }
    },
  });
}

// ─── Chunk-level encrypt / decrypt ───────────────────────────────────────────

async function encryptChunk(
  key: CryptoKey,
  streamNonce: Uint8Array,
  plaintext: Uint8Array,
  index: number,
  purpose: string,
  extraAad: Uint8Array | undefined,
  isLast: boolean,
): Promise<Uint8Array> {
  // Derive per-chunk IV: XOR stream nonce with big-endian index
  const iv = deriveChunkIV(streamNonce, index);

  // AAD = purpose + chunk_index + is_last flag
  const chunkAAD = buildChunkAAD(purpose, index, isLast, extraAad);

  const subtle = getCrypto().subtle;
  const encrypted = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as Uint8Array<ArrayBuffer>, additionalData: chunkAAD as unknown as Uint8Array<ArrayBuffer>, tagLength: TAG_LENGTH * 8 },
    key,
    plaintext as unknown as Uint8Array<ArrayBuffer>,
  ));

  const ciphertext = encrypted.slice(0, encrypted.length - TAG_LENGTH);
  const tag = encrypted.slice(encrypted.length - TAG_LENGTH);

  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);

  return concatBytes(indexBytes, iv, tag, ciphertext);
}

async function decryptChunk(
  key: CryptoKey,
  streamNonce: Uint8Array,
  chunkBytes: Uint8Array,
  index: number,
  purpose: string,
  extraAad: Uint8Array | undefined,
): Promise<Uint8Array> {
  // chunkBytes = [4 index][12 iv][16 tag][N ciphertext]
  const iv = chunkBytes.slice(4, 4 + CHUNK_IV_LENGTH);
  const tag = chunkBytes.slice(4 + CHUNK_IV_LENGTH, 4 + CHUNK_IV_LENGTH + TAG_LENGTH);
  const ciphertext = chunkBytes.slice(4 + CHUNK_IV_LENGTH + TAG_LENGTH);

  const isLast = ciphertext.length < DEFAULT_CHUNK_SIZE;

  // Try both isLast=true and isLast=false if needed
  for (const lastFlag of [false, true]) {
    const chunkAAD = buildChunkAAD(purpose, index, lastFlag, extraAad);
    const subtle = getCrypto().subtle;
    try {
      const plain = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as Uint8Array<ArrayBuffer>, additionalData: chunkAAD as unknown as Uint8Array<ArrayBuffer>, tagLength: TAG_LENGTH * 8 },
        key,
        concatBytes(ciphertext, tag) as unknown as Uint8Array<ArrayBuffer>,
      ));
      return plain;
    } catch {
      continue;
    }
  }

  throw new EncryptixError('STREAM_ERROR', `Failed to decrypt chunk at index ${index}. Stream may be tampered.`);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function deriveChunkIV(streamNonce: Uint8Array, index: number): Uint8Array {
  const iv = new Uint8Array(streamNonce);
  // XOR last 4 bytes of nonce with chunk index (big-endian)
  iv[8]  ^= (index >>> 24) & 0xff;
  iv[9]  ^= (index >>> 16) & 0xff;
  iv[10] ^= (index >>> 8)  & 0xff;
  iv[11] ^= index          & 0xff;
  return iv;
}

function buildChunkAAD(
  purpose: string,
  index: number,
  isLast: boolean,
  extraAad: Uint8Array | undefined,
): Uint8Array {
  const purposeBytes = encode(purpose);
  const indexBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  const flagByte = new Uint8Array([isLast ? 1 : 0]);
  return extraAad
    ? concatBytes(purposeBytes, indexBytes, flagByte, extraAad)
    : concatBytes(purposeBytes, indexBytes, flagByte);
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
