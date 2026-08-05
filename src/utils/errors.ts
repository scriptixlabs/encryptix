import type { EncryptixErrorCode } from '../types/index.js';

/**
 * Structured error thrown by all @scriptixlabs/encryptix operations.
 * Always carries a machine-readable `code` so callers can handle
 * specific failure modes without parsing message strings.
 */
export class EncryptixError extends Error {
  public readonly code: EncryptixErrorCode;
  public readonly cause?: unknown;

  constructor(code: EncryptixErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'EncryptixError';
    this.code = code;
    this.cause = cause;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EncryptixError);
    }
  }

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
  static from(
    err: unknown,
    code: EncryptixErrorCode = 'ENCRYPTION_FAILED',
    message?: string,
  ): EncryptixError {
    if (err instanceof EncryptixError) return err;
    const msg = message ?? (err instanceof Error ? err.message : String(err));
    return new EncryptixError(code, msg, err);
  }

  /**
   * Returns true if the error has a specific code.
   * Useful for type-safe error handling in catch blocks.
   *
   * @example
   * if (EncryptixError.is(err, 'PAYLOAD_EXPIRED')) { ... }
   */
  static is(err: unknown, code: EncryptixErrorCode): err is EncryptixError {
    return err instanceof EncryptixError && err.code === code;
  }

  /**
   * Returns true if the error is any EncryptixError.
   */
  static isEncryptixError(err: unknown): err is EncryptixError {
    return err instanceof EncryptixError;
  }

  override toString(): string {
    return `EncryptixError [${this.code}]: ${this.message}`;
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}
