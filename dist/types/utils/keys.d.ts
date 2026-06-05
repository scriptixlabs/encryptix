/**
 * Generates a cryptographically strong 256-bit (32-byte) master key.
 * Returns a 64-character lowercase hex string.
 *
 * Store this in your environment: ENCRYPTIX_KEY=<output>
 */
export declare function generateMasterKey(): string;
/**
 * Validates a master key hex string.
 * Must be exactly 64 hex characters (32 bytes / 256 bits).
 */
export declare function validateMasterKey(key: string): void;
/**
 * Resolves the master key from:
 * 1. The explicitly provided value
 * 2. The ENCRYPTIX_KEY environment variable
 * 3. Throws if neither is set
 */
export declare function resolveMasterKey(explicit?: string): string;
/**
 * Resolves a key from the keychain by version number.
 * Used during decryption with key rotation.
 */
export declare function resolveKeychainKey(keychain: Record<number, string>, version: number): string;
//# sourceMappingURL=keys.d.ts.map