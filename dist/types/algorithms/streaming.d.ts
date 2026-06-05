/**
 * Streaming Encryption for @ppabari/encryptix
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
import type { StreamEncryptOptions, StreamDecryptOptions, HashAlgorithm } from '../types/index.js';
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
export declare function createEncryptStream(masterKeyHex: string, namespace: string, hashAlg: HashAlgorithm, options: StreamEncryptOptions): TransformStream<Uint8Array, Uint8Array>;
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
export declare function createDecryptStream(masterKeyHex: string, namespace: string, hashAlg: HashAlgorithm, options: StreamDecryptOptions): TransformStream<Uint8Array, Uint8Array>;
//# sourceMappingURL=streaming.d.ts.map