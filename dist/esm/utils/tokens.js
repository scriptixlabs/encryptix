/**
 * Hashing, HMAC signing, and secure token generation utilities.
 * All functions use the Web Crypto API where possible for cross-runtime compatibility.
 */
import { getCrypto, encode, bytesToHex, hexToBytes, bytesToBase64 } from './env.js';
import { EncryptixError } from './errors.js';
// ─── Hashing ─────────────────────────────────────────────────────────────────
/**
 * SHA-256 / SHA-384 / SHA-512 hash of a string or bytes.
 * Constant across all runtimes via Web Crypto.
 */
export async function hash(input, algorithm = 'sha256', encoding = 'hex') {
    const data = typeof input === 'string' ? encode(input) : input;
    const webAlgo = toWebHashAlgo(algorithm);
    let digest;
    try {
        digest = await getCrypto().subtle.digest(webAlgo, data);
    }
    catch (err) {
        throw new EncryptixError('ENCRYPTION_FAILED', `Hashing with ${algorithm} failed.`, err);
    }
    const bytes = new Uint8Array(digest);
    if (encoding === 'base64')
        return bytesToBase64(bytes);
    if (encoding === 'base64url')
        return bytesToBase64(bytes, true);
    return bytesToHex(bytes);
}
// ─── HMAC ─────────────────────────────────────────────────────────────────────
/**
 * Produces an HMAC signature for a message using the given key.
 * Returns a hex string by default.
 */
export async function hmac(message, keyHex, algorithm = 'sha256', encoding = 'hex') {
    const subtle = getCrypto().subtle;
    const webAlgo = toWebHashAlgo(algorithm);
    const cryptoKey = await subtle.importKey('raw', hexToBytes(keyHex), { name: 'HMAC', hash: webAlgo }, false, ['sign']);
    const data = typeof message === 'string' ? encode(message) : message;
    let signature;
    try {
        signature = await subtle.sign('HMAC', cryptoKey, data);
    }
    catch (err) {
        throw new EncryptixError('ENCRYPTION_FAILED', 'HMAC signing failed.', err);
    }
    const bytes = new Uint8Array(signature);
    if (encoding === 'base64')
        return bytesToBase64(bytes);
    if (encoding === 'base64url')
        return bytesToBase64(bytes, true);
    return bytesToHex(bytes);
}
/**
 * Verifies an HMAC signature in constant time.
 * Returns true if valid, false otherwise.
 */
export async function verifyHmac(message, keyHex, signature, algorithm = 'sha256', encoding = 'hex') {
    const expected = await hmac(message, keyHex, algorithm, encoding);
    // Constant-time compare via XOR over char codes
    if (expected.length !== signature.length)
        return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
        diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return diff === 0;
}
// ─── Token Generation ─────────────────────────────────────────────────────────
/**
 * Generates a cryptographically random token.
 * @param bytes  - Number of random bytes (default: 32 → 64-char hex)
 * @param encoding - Output format
 */
export function generateToken(bytes = 32, encoding = 'hex') {
    const arr = getCrypto().getRandomValues(new Uint8Array(bytes));
    if (encoding === 'base64')
        return bytesToBase64(arr);
    if (encoding === 'base64url')
        return bytesToBase64(arr, true);
    return bytesToHex(arr);
}
/**
 * Generates a secure random API key in the format `{prefix}_{base64url_random}`.
 * @example generateApiKey('sk') → 'sk_4xG9...'
 */
export function generateApiKey(prefix = 'key', bytes = 32) {
    const token = generateToken(bytes, 'base64url');
    return `${prefix}_${token}`;
}
/**
 * Generates a UUID v4 using the platform's crypto.randomUUID if available,
 * falling back to manual construction.
 */
export function generateUUID() {
    if (typeof getCrypto().randomUUID === 'function') {
        return getCrypto().randomUUID();
    }
    // Manual fallback
    const bytes = getCrypto().getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant bits
    const hex = bytesToHex(bytes);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function toWebHashAlgo(alg) {
    return alg.toUpperCase().replace('SHA', 'SHA-'); // sha256 → SHA-256
}
//# sourceMappingURL=tokens.js.map