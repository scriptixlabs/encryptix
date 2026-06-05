/**
 * Memory Safety, Key Lifecycle & Migration Utilities
 *
 * - zeroize:       Wipe sensitive bytes from memory after use
 * - KeyMetadata:   Associate metadata (created-at, purpose, algo) with key versions
 * - reEncrypt:     Migrate payloads between purposes or keys
 * - Key I/O:       Import/export keys in JWK, hex, and PEM formats
 */
import { getCrypto, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } from './env.js';
import { EncryptixError } from './errors.js';
// ─── Zeroize ─────────────────────────────────────────────────────────────────
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
export function zeroize(buffer) {
    buffer.fill(0);
}
/**
 * Zeroize multiple buffers at once.
 */
export function zeroizeAll(...buffers) {
    for (const buf of buffers)
        buf.fill(0);
}
/**
 * Run a function with a key buffer, then zeroize it regardless of outcome.
 *
 * @example
 * const result = await withZeroize(hexToBytes(keyHex), async (keyBuf) => {
 *   return doSomethingWithKey(keyBuf);
 * });
 */
export async function withZeroize(buffer, fn) {
    try {
        return await fn(buffer);
    }
    finally {
        zeroize(buffer);
    }
}
// ─── Key Metadata Store ───────────────────────────────────────────────────────
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
export function createKeyMetadataStore() {
    const entries = new Map();
    return {
        register(version, metadata) {
            if (!Number.isInteger(version) || version < 1) {
                throw new EncryptixError('INVALID_KEY', `Key version must be a positive integer, got ${version}.`);
            }
            entries.set(version, { ...metadata, version });
        },
        get(version) {
            const meta = entries.get(version);
            if (!meta) {
                throw new EncryptixError('KEY_NOT_FOUND', `No metadata registered for key version ${version}.`);
            }
            return meta;
        },
        has(version) {
            return entries.has(version);
        },
        versions() {
            return [...entries.keys()].sort((a, b) => a - b);
        },
        latest() {
            const vers = [...entries.keys()];
            if (!vers.length)
                return null;
            return entries.get(Math.max(...vers));
        },
        summary() {
            return [...entries.values()].sort((a, b) => a.version - b.version);
        },
        /** Build a keychain object compatible with EncryptixClient({ keychain }) */
        toKeychain() {
            const chain = {};
            for (const [version, meta] of entries) {
                chain[version] = meta.keyHex;
            }
            return chain;
        },
    };
}
// ─── reEncrypt ────────────────────────────────────────────────────────────────
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
export async function reEncrypt(payload, from, to) {
    let plaintext;
    try {
        plaintext = await from.decryptFn(payload, from.purpose, from.options);
    }
    catch (err) {
        throw new EncryptixError('DECRYPTION_FAILED', `reEncrypt: failed to decrypt source payload with purpose '${from.purpose}'.`, err);
    }
    try {
        return await to.encryptFn(plaintext, to.purpose, to.options);
    }
    catch (err) {
        throw new EncryptixError('ENCRYPTION_FAILED', `reEncrypt: failed to re-encrypt with purpose '${to.purpose}'.`, err);
    }
}
/**
 * Re-encrypt a batch of payloads.
 * Returns results in the same order as input. Errors per-item if `safe` is true.
 */
export async function reEncryptBatch(payloads, from, to, safe = false) {
    return Promise.all(payloads.map(async (payload, index) => {
        try {
            const newPayload = await reEncrypt(payload, from, to);
            return { ok: true, payload: newPayload, index };
        }
        catch (err) {
            if (!safe)
                throw err;
            return { ok: false, error: String(err), index };
        }
    }));
}
// ─── Key Import / Export ─────────────────────────────────────────────────────
/**
 * Export a symmetric key hex string to JWK format.
 * JWK is the standard portable key format for Web Crypto interoperability.
 */
export async function exportKeyToJWK(keyHex) {
    const subtle = getCrypto().subtle;
    const keyBytes = hexToBytes(keyHex);
    const cryptoKey = await subtle.importKey('raw', keyBytes, 'AES-GCM', true, ['encrypt', 'decrypt']);
    return subtle.exportKey('jwk', cryptoKey);
}
/**
 * Import a JWK symmetric key to a hex string for use with EncryptixClient.
 */
export async function importKeyFromJWK(jwk) {
    const subtle = getCrypto().subtle;
    let cryptoKey;
    try {
        cryptoKey = await subtle.importKey('jwk', jwk, 'AES-GCM', true, ['encrypt', 'decrypt']);
    }
    catch (err) {
        throw new EncryptixError('INVALID_KEY', 'Failed to import key from JWK.', err);
    }
    const raw = await subtle.exportKey('raw', cryptoKey);
    return bytesToHex(new Uint8Array(raw));
}
/**
 * Serialize a hex key to a portable string format.
 * Supports: 'hex' (default), 'base64', 'base64url', 'jwk'.
 */
export async function serializeKey(keyHex, format = 'hex') {
    if (format === 'hex')
        return keyHex;
    if (format === 'base64')
        return bytesToBase64(hexToBytes(keyHex), false);
    if (format === 'base64url')
        return bytesToBase64(hexToBytes(keyHex), true);
    if (format === 'jwk')
        return JSON.stringify(await exportKeyToJWK(keyHex));
    throw new EncryptixError('INVALID_KEY', `Unknown key format: ${format}`);
}
/**
 * Deserialize a key from a portable string format back to hex.
 */
export async function deserializeKey(input, format = 'hex') {
    if (format === 'hex')
        return input;
    if (format === 'base64' || format === 'base64url')
        return bytesToHex(base64ToBytes(input));
    if (format === 'jwk') {
        try {
            const jwk = JSON.parse(input);
            return importKeyFromJWK(jwk);
        }
        catch (err) {
            throw new EncryptixError('INVALID_KEY', 'Failed to parse or import JWK string.', err);
        }
    }
    throw new EncryptixError('INVALID_KEY', `Unknown key format: ${format}`);
}
//# sourceMappingURL=zeroize.js.map