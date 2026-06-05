/**
 * Cryptographically Secure Random Utilities
 *
 * All functions use crypto.getRandomValues() — never Math.random().
 *
 * The key invariant for secureRandomInt: rejection sampling ensures
 * every value in [min, max] has exactly equal probability, avoiding
 * the modulo bias that plagues naive implementations.
 */
import { getCrypto } from './env.js';
import { EncryptixError } from './errors.js';
// ─── Random Bytes ─────────────────────────────────────────────────────────────
/**
 * Generate `n` cryptographically random bytes.
 */
export function secureRandomBytes(n) {
    if (n < 1 || !Number.isInteger(n)) {
        throw new EncryptixError('INVALID_INPUT', `secureRandomBytes: n must be a positive integer, got ${n}`);
    }
    return getCrypto().getRandomValues(new Uint8Array(n));
}
// ─── Random Integer ───────────────────────────────────────────────────────────
/**
 * Generate a cryptographically secure random integer in [min, max] (inclusive).
 *
 * Uses rejection sampling to eliminate modulo bias — every integer in the
 * range has exactly equal probability regardless of range size.
 *
 * @example
 * secureRandomInt(1, 6)   // dice roll
 * secureRandomInt(0, 255) // random byte value
 * secureRandomInt(100000, 999999) // 6-digit OTP (use TOTP instead for real auth)
 */
export function secureRandomInt(min, max) {
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
        throw new EncryptixError('INVALID_INPUT', 'secureRandomInt: min and max must be integers.');
    }
    if (min > max) {
        throw new EncryptixError('INVALID_INPUT', `secureRandomInt: min (${min}) must be ≤ max (${max}).`);
    }
    if (min === max)
        return min;
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8) + 1;
    const maxValid = Math.floor(0x100 ** bytesNeeded / range) * range;
    const buf = new Uint8Array(bytesNeeded);
    let value;
    do {
        getCrypto().getRandomValues(buf);
        value = buf.reduce((acc, byte) => acc * 256 + byte, 0);
    } while (value >= maxValid);
    return min + (value % range);
}
// ─── Random Float ────────────────────────────────────────────────────────────
/**
 * Generate a cryptographically secure random float in [0, 1).
 * Suitable for random selection, sampling, and probabilistic algorithms.
 */
export function secureRandomFloat() {
    const buf = new Uint32Array(1);
    getCrypto().getRandomValues(buf);
    return buf[0] / 0x100000000;
}
// ─── Random String ───────────────────────────────────────────────────────────
/** Default charset: URL-safe base62 */
const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
/** Charsets for common use cases */
export const CHARSETS = {
    /** URL-safe alphanumeric (default) */
    alphanumeric: BASE62,
    /** Lowercase alphanumeric — easy to type/read */
    lowercase: 'abcdefghijklmnopqrstuvwxyz0123456789',
    /** Uppercase alphanumeric */
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    /** Hex digits */
    hex: '0123456789abcdef',
    /** Digits only — for numeric OTPs (prefer generateTOTP for 2FA) */
    numeric: '0123456789',
    /** URL-safe: alphanumeric + - _ */
    urlSafe: `${BASE62}-_`,
    /** Human-readable: removes visually ambiguous chars (0, O, l, 1, I) */
    readable: 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789',
    /** Full printable ASCII (strong passwords) */
    printable: '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
};
/**
 * Generate a cryptographically random string of the given length.
 * Uses rejection sampling to ensure uniform distribution across the charset.
 *
 * @example
 * secureRandomString(32)                        // 32-char alphanumeric
 * secureRandomString(16, 'readable')            // ambiguous-char-free
 * secureRandomString(20, 'printable')           // strong password
 * secureRandomString(8,  '0123456789')          // 8-digit numeric code
 */
export function secureRandomString(length, charset = 'alphanumeric') {
    if (length < 1 || !Number.isInteger(length)) {
        throw new EncryptixError('INVALID_INPUT', `secureRandomString: length must be a positive integer, got ${length}`);
    }
    const chars = typeof charset === 'string' && charset in CHARSETS
        ? CHARSETS[charset]
        : charset;
    if (chars.length < 2) {
        throw new EncryptixError('INVALID_INPUT', 'secureRandomString: charset must have at least 2 characters.');
    }
    if (chars.length > 256) {
        throw new EncryptixError('INVALID_INPUT', 'secureRandomString: charset must have ≤ 256 characters.');
    }
    // Rejection sampling per character to eliminate modulo bias
    const maxValid = Math.floor(256 / chars.length) * chars.length;
    const result = [];
    const buf = new Uint8Array(length * 2); // generate extra to reduce loop iterations
    while (result.length < length) {
        getCrypto().getRandomValues(buf);
        for (let i = 0; i < buf.length && result.length < length; i++) {
            if (buf[i] < maxValid) {
                result.push(chars[buf[i] % chars.length]);
            }
        }
    }
    return result.join('');
}
// ─── Random Choice ───────────────────────────────────────────────────────────
/**
 * Select one random element from an array with equal probability.
 *
 * @example
 * secureRandomChoice(['rock', 'paper', 'scissors'])
 * secureRandomChoice(userIds) // random user selection
 */
export function secureRandomChoice(array) {
    if (!array.length) {
        throw new EncryptixError('INVALID_INPUT', 'secureRandomChoice: array must not be empty.');
    }
    return array[secureRandomInt(0, array.length - 1)];
}
/**
 * Select `n` unique random elements from an array (sampling without replacement).
 *
 * @example
 * secureRandomSample(['a','b','c','d','e'], 3) // 3 unique items
 */
export function secureRandomSample(array, n) {
    if (n > array.length) {
        throw new EncryptixError('INVALID_INPUT', `secureRandomSample: n (${n}) exceeds array length (${array.length}).`);
    }
    // Fisher-Yates partial shuffle
    const pool = [...array];
    const result = [];
    for (let i = 0; i < n; i++) {
        const j = secureRandomInt(i, pool.length - 1);
        [pool[i], pool[j]] = [pool[j], pool[i]];
        result.push(pool[i]);
    }
    return result;
}
/**
 * Shuffle an array using the Fisher-Yates algorithm with crypto randomness.
 * Returns a new array — does not mutate the input.
 *
 * @example
 * secureRandomShuffle([1, 2, 3, 4, 5])
 */
export function secureRandomShuffle(array) {
    const result = [...array];
    for (let i = result.length - 1; i > 0; i--) {
        const j = secureRandomInt(0, i);
        [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
}
// ─── Passphrase Generation ────────────────────────────────────────────────────
/**
 * Generate a random passphrase from a word list.
 * A 4-word passphrase from a 2048-word list has ~44 bits of entropy.
 * A 6-word passphrase has ~66 bits — stronger than most passwords.
 *
 * @example
 * securePassphrase(WORDLIST, 6, '-')
 * // → 'correct-horse-battery-staple-river-cloud'
 */
export function securePassphrase(wordList, wordCount = 5, separator = '-') {
    if (wordList.length < 100) {
        throw new EncryptixError('INVALID_INPUT', 'securePassphrase: wordList must have at least 100 words for adequate entropy.');
    }
    return Array.from({ length: wordCount }, () => secureRandomChoice(wordList)).join(separator);
}
//# sourceMappingURL=random.js.map