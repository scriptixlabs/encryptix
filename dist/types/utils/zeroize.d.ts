/**
 * Memory Safety, Key Lifecycle & Migration Utilities
 *
 * - zeroize:       Wipe sensitive bytes from memory after use
 * - KeyMetadata:   Associate metadata (created-at, purpose, algo) with key versions
 * - reEncrypt:     Migrate payloads between purposes or keys
 * - Key I/O:       Import/export keys in JWK, hex, and PEM formats
 */
import type { KeyMetadataStore, ReEncryptOptions, KeyExportFormat } from '../types/index.js';
/**
 * Overwrite a Uint8Array with zeros to wipe sensitive data from memory.
 *
 * JavaScript's GC makes it impossible to guarantee memory is wiped, but
 * calling zeroize immediately after use is still best practice — it reduces
 * the window during which a heap dump or memory scanner could find the data.
 *
 * Note: Non-extractable CryptoKey objects (Web Crypto) are managed by the
 * runtime and cannot be manually zeroed. Use them where possible.
 *
 * @example
 * const keyBytes = hexToBytes(masterKeyHex);
 * try {
 *   await doSomethingWithKey(keyBytes);
 * } finally {
 *   zeroize(keyBytes);
 * }
 */
export declare function zeroize(buffer: Uint8Array): void;
/**
 * Zeroize multiple buffers at once.
 */
export declare function zeroizeAll(...buffers: Uint8Array[]): void;
/**
 * Run a function with a key buffer, then zeroize it regardless of outcome.
 *
 * @example
 * const result = await withZeroize(hexToBytes(keyHex), async (keyBuf) => {
 *   return doSomethingWithKey(keyBuf);
 * });
 */
export declare function withZeroize<T>(buffer: Uint8Array, fn: (buffer: Uint8Array) => Promise<T>): Promise<T>;
/**
 * Create a key metadata store — a lightweight in-memory registry that
 * associates metadata with each key version in your keychain.
 *
 * Metadata helps answer: "which key is this? when was it created? why does it exist?"
 *
 * @example
 * const store = createKeyMetadataStore();
 * store.register(1, { keyHex: oldKey, purpose: 'user:data', createdAt: new Date('2024-01-01') });
 * store.register(2, { keyHex: newKey, purpose: 'user:data', createdAt: new Date('2025-06-01') });
 *
 * console.log(store.get(1).createdAt);     // 2024-01-01
 * console.log(store.summary());            // [{ version: 1, ... }, { version: 2, ... }]
 */
export declare function createKeyMetadataStore(): KeyMetadataStore;
/**
 * Decrypt a payload and re-encrypt it with a new purpose, key, or algorithm.
 *
 * Common use cases:
 *   - Renaming a purpose string (e.g. 'email' → 'user:pii:email')
 *   - Migrating payloads to a new master key after rotation
 *   - Changing algorithm (aes-256-gcm → chacha20-poly1305)
 *
 * The plaintext is in memory only for the duration of this call.
 *
 * @example
 * // Rename purpose during a migration
 * const newPayload = await reEncrypt(
 *   oldPayload,
 *   { decryptFn: oldClient.decrypt.bind(oldClient), purpose: 'email' },
 *   { encryptFn: newClient.encrypt.bind(newClient), purpose: 'user:pii:email' },
 * );
 */
export declare function reEncrypt(payload: string, from: ReEncryptOptions, to: ReEncryptOptions): Promise<string>;
/**
 * Re-encrypt a batch of payloads.
 * Returns results in the same order as input. Errors per-item if `safe` is true.
 */
export declare function reEncryptBatch(payloads: string[], from: ReEncryptOptions, to: ReEncryptOptions, safe?: boolean): Promise<Array<{
    ok: boolean;
    payload?: string;
    error?: string;
    index: number;
}>>;
/**
 * Export a symmetric key hex string to JWK format.
 * JWK is the standard portable key format for Web Crypto interoperability.
 */
export declare function exportKeyToJWK(keyHex: string): Promise<JsonWebKey>;
/**
 * Import a JWK symmetric key to a hex string for use with EncryptixClient.
 */
export declare function importKeyFromJWK(jwk: JsonWebKey): Promise<string>;
/**
 * Serialize a hex key to a portable string format.
 * Supports: 'hex' (default), 'base64', 'base64url', 'jwk'.
 */
export declare function serializeKey(keyHex: string, format?: KeyExportFormat): Promise<string>;
/**
 * Deserialize a key from a portable string format back to hex.
 */
export declare function deserializeKey(input: string, format?: KeyExportFormat): Promise<string>;
//# sourceMappingURL=zeroize.d.ts.map