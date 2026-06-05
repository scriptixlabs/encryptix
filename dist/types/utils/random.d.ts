/**
 * Cryptographically Secure Random Utilities
 *
 * All functions use crypto.getRandomValues() — never Math.random().
 *
 * The key invariant for secureRandomInt: rejection sampling ensures
 * every value in [min, max] has exactly equal probability, avoiding
 * the modulo bias that plagues naive implementations.
 */
/**
 * Generate `n` cryptographically random bytes.
 */
export declare function secureRandomBytes(n: number): Uint8Array;
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
export declare function secureRandomInt(min: number, max: number): number;
/**
 * Generate a cryptographically secure random float in [0, 1).
 * Suitable for random selection, sampling, and probabilistic algorithms.
 */
export declare function secureRandomFloat(): number;
/** Charsets for common use cases */
export declare const CHARSETS: {
    /** URL-safe alphanumeric (default) */
    readonly alphanumeric: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    /** Lowercase alphanumeric — easy to type/read */
    readonly lowercase: "abcdefghijklmnopqrstuvwxyz0123456789";
    /** Uppercase alphanumeric */
    readonly uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /** Hex digits */
    readonly hex: "0123456789abcdef";
    /** Digits only — for numeric OTPs (prefer generateTOTP for 2FA) */
    readonly numeric: "0123456789";
    /** URL-safe: alphanumeric + - _ */
    readonly urlSafe: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    /** Human-readable: removes visually ambiguous chars (0, O, l, 1, I) */
    readonly readable: "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    /** Full printable ASCII (strong passwords) */
    readonly printable: "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
};
export type Charset = keyof typeof CHARSETS;
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
export declare function secureRandomString(length: number, charset?: Charset | string): string;
/**
 * Select one random element from an array with equal probability.
 *
 * @example
 * secureRandomChoice(['rock', 'paper', 'scissors'])
 * secureRandomChoice(userIds) // random user selection
 */
export declare function secureRandomChoice<T>(array: readonly T[]): T;
/**
 * Select `n` unique random elements from an array (sampling without replacement).
 *
 * @example
 * secureRandomSample(['a','b','c','d','e'], 3) // 3 unique items
 */
export declare function secureRandomSample<T>(array: readonly T[], n: number): T[];
/**
 * Shuffle an array using the Fisher-Yates algorithm with crypto randomness.
 * Returns a new array — does not mutate the input.
 *
 * @example
 * secureRandomShuffle([1, 2, 3, 4, 5])
 */
export declare function secureRandomShuffle<T>(array: readonly T[]): T[];
/**
 * Generate a random passphrase from a word list.
 * A 4-word passphrase from a 2048-word list has ~44 bits of entropy.
 * A 6-word passphrase has ~66 bits — stronger than most passwords.
 *
 * @example
 * securePassphrase(WORDLIST, 6, '-')
 * // → 'correct-horse-battery-staple-river-cloud'
 */
export declare function securePassphrase(wordList: readonly string[], wordCount?: number, separator?: string): string;
//# sourceMappingURL=random.d.ts.map