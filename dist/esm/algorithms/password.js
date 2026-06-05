/**
 * Password-Based Key Derivation for @ppabari/encryptix
 *
 * Two backends:
 *   scrypt  — Node.js only. Memory-hard, GPU-resistant. STRONGLY preferred for Node.
 *   pbkdf2  — Universal (Web Crypto). For browsers and edge runtimes.
 *             Uses 600,000 iterations per OWASP 2023 guidance.
 *
 * The output `keyHex` is a 64-char hex string, ready to pass directly to
 * `new EncryptixClient({ key: keyHex })`.
 *
 * CRITICAL: Always store the returned `saltHex` alongside encrypted data.
 * Without the same salt, you cannot re-derive the same key.
 *
 * @example
 * ```ts
 * const { keyHex, saltHex } = await deriveKeyFromPassword('my-passphrase', 'user:vault');
 * const enc = new EncryptixClient({ key: keyHex });
 * // store saltHex in your DB next to the encrypted payload
 *
 * // Later, to decrypt:
 * const { keyHex } = await deriveKeyFromPassword('my-passphrase', 'user:vault', { saltHex });
 * const enc = new EncryptixClient({ key: keyHex });
 * ```
 */
import { getCrypto, RUNTIME, bytesToHex, hexToBytes, encode } from '../utils/env.js';
import { EncryptixError } from '../utils/errors.js';
// ─── Defaults ────────────────────────────────────────────────────────────────
const SCRYPT_N = 131072; // 2^17 — OWASP interactive login recommendation
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const PBKDF2_ITERATIONS = 600000; // OWASP 2023
const SALT_LENGTH = 32; // 256-bit salt
const DEFAULT_KEY_LENGTH = 32; // 256-bit output
// ─── Public API ──────────────────────────────────────────────────────────────
/**
 * Derives a cryptographic key from a human password.
 *
 * @param password - The user's password or passphrase
 * @param purpose  - Domain-separation label (included in KDF info, not the salt)
 * @param options  - KDF options (algorithm, salt, cost params)
 */
export async function deriveKeyFromPassword(password, purpose, options = {}) {
    if (!password) {
        throw new EncryptixError('PASSWORD_KDF_FAILED', 'Password must be a non-empty string.');
    }
    const algorithm = options.algorithm ?? (RUNTIME === 'node' ? 'scrypt' : 'pbkdf2');
    const saltBytes = options.saltHex
        ? hexToBytes(options.saltHex)
        : getCrypto().getRandomValues(new Uint8Array(SALT_LENGTH));
    const keyLength = options.keyLength ?? DEFAULT_KEY_LENGTH;
    // Mix the purpose into the salt so the same password + salt produces
    // different keys for different purposes (extra layer of separation).
    const purposedSalt = await mixPurposeIntoSalt(saltBytes, purpose);
    let keyBytes;
    let params;
    if (algorithm === 'scrypt') {
        if (RUNTIME !== 'node') {
            throw new EncryptixError('ENVIRONMENT_UNSUPPORTED', 'scrypt is only available in Node.js. Use algorithm: "pbkdf2" for browser/edge.');
        }
        const N = options.scryptN ?? SCRYPT_N;
        const r = options.scryptR ?? SCRYPT_R;
        const p = options.scryptP ?? SCRYPT_P;
        keyBytes = await scryptDerive(password, purposedSalt, N, r, p, keyLength);
        params = { scryptN: N, scryptR: r, scryptP: p, keyLength };
    }
    else {
        const iterations = options.pbkdf2Iterations ?? PBKDF2_ITERATIONS;
        keyBytes = await pbkdf2Derive(password, purposedSalt, iterations, keyLength);
        params = { pbkdf2Iterations: iterations, keyLength };
    }
    return {
        keyHex: bytesToHex(keyBytes),
        saltHex: bytesToHex(saltBytes), // return ORIGINAL salt (without purpose mix) for storage
        algorithm,
        params,
    };
}
// ─── scrypt (Node native) ────────────────────────────────────────────────────
async function scryptDerive(password, salt, N, r, p, keyLength) {
    const { promisify } = await import('util');
    const { scrypt } = await import('crypto');
    const scryptAsync = promisify(scrypt);
    try {
        const result = await scryptAsync(Buffer.from(password, 'utf8'), Buffer.from(salt), keyLength, { N, r, p, maxmem: 128 * N * r * 2 });
        return new Uint8Array(result);
    }
    catch (err) {
        throw new EncryptixError('PASSWORD_KDF_FAILED', 'scrypt key derivation failed.', err);
    }
}
// ─── PBKDF2 (Web Crypto — universal) ─────────────────────────────────────────
async function pbkdf2Derive(password, salt, iterations, keyLength) {
    const subtle = getCrypto().subtle;
    let keyMaterial;
    try {
        keyMaterial = await subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveBits']);
    }
    catch (err) {
        throw new EncryptixError('PASSWORD_KDF_FAILED', 'Failed to import password as PBKDF2 key material.', err);
    }
    try {
        const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations }, keyMaterial, keyLength * 8);
        return new Uint8Array(bits);
    }
    catch (err) {
        throw new EncryptixError('PASSWORD_KDF_FAILED', 'PBKDF2 key derivation failed.', err);
    }
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
/**
 * Mixes the purpose string into the salt via HMAC-SHA256.
 * This ensures password + salt for "user:vault" produces a different key
 * than password + same salt for "admin:vault" — without changing the stored salt.
 */
async function mixPurposeIntoSalt(salt, purpose) {
    const subtle = getCrypto().subtle;
    const key = await subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await subtle.sign('HMAC', key, encode(purpose));
    return new Uint8Array(sig);
}
//# sourceMappingURL=password.js.map