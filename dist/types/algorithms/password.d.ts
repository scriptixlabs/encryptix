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
import type { DeriveKeyFromPasswordOptions, DerivedPasswordKey } from '../types/index.js';
/**
 * Derives a cryptographic key from a human password.
 *
 * @param password - The user's password or passphrase
 * @param purpose  - Domain-separation label (included in KDF info, not the salt)
 * @param options  - KDF options (algorithm, salt, cost params)
 */
export declare function deriveKeyFromPassword(password: string, purpose: string, options?: DeriveKeyFromPasswordOptions): Promise<DerivedPasswordKey>;
//# sourceMappingURL=password.d.ts.map