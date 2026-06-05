import type { EncryptixErrorCode } from '../types/index.js';
/**
 * Structured error thrown by all @ppabari/encryptix operations.
 * Always carries a machine-readable `code` so callers can handle
 * specific failure modes without parsing message strings.
 */
export declare class EncryptixError extends Error {
    readonly code: EncryptixErrorCode;
    readonly cause?: unknown;
    constructor(code: EncryptixErrorCode, message: string, cause?: unknown);
    /**
     * Wrap any unknown error as an EncryptixError.
     * Useful when bridging errors from external operations (DB calls, network, etc.)
     * into the encryptix error hierarchy.
     *
     * If the error is already an EncryptixError, it is returned as-is.
     *
     * @example
     * try {
     *   const key = await fetchKeyFromVault();
     *   // ...
     * } catch (err) {
     *   throw EncryptixError.from(err, 'INVALID_KEY', 'Failed to fetch key from vault');
     * }
     */
    static from(err: unknown, code?: EncryptixErrorCode, message?: string): EncryptixError;
    /**
     * Returns true if the error has a specific code.
     * Useful for type-safe error handling in catch blocks.
     *
     * @example
     * if (EncryptixError.is(err, 'PAYLOAD_EXPIRED')) { ... }
     */
    static is(err: unknown, code: EncryptixErrorCode): err is EncryptixError;
    /**
     * Returns true if the error is any EncryptixError.
     */
    static isEncryptixError(err: unknown): err is EncryptixError;
    toString(): string;
    toJSON(): Record<string, unknown>;
}
//# sourceMappingURL=errors.d.ts.map