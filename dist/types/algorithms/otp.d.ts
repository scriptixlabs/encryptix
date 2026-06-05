/**
 * TOTP (Time-based One-Time Password) + HOTP (HMAC-based OTP)
 * RFC 6238 (TOTP) + RFC 4226 (HOTP)
 *
 * Compatible with Google Authenticator, Authy, 1Password, and any
 * RFC-compliant TOTP app.
 *
 * Usage:
 *   1. Generate a secret:  const secret = generateTOTPSecret()
 *   2. Show QR code:       totpKeyUri(secret, 'user@example.com', 'MyApp')
 *   3. Verify codes:       await verifyTOTP(userCode, secret)
 *
 * Security:
 *   - Uses HMAC-SHA1 per RFC 4226 (authenticator app compatibility)
 *   - Window of ±1 step (30s) to account for clock skew
 *   - Constant-time comparison to prevent timing attacks
 *   - Secrets stored as base32 (standard format for authenticator apps)
 */
import type { TOTPOptions, HOTPOptions, TOTPVerifyResult } from '../types/index.js';
/**
 * Generate a cryptographically random TOTP secret.
 * Returns a base32-encoded string (the standard format for authenticator apps).
 *
 * @param bytes - Secret length in bytes. 20 bytes = 160 bits (RFC minimum).
 */
export declare function generateTOTPSecret(bytes?: number): string;
/**
 * Generate a TOTP key URI for QR code generation.
 * The URI can be encoded into a QR code and scanned by any authenticator app.
 *
 * @example
 * const uri = totpKeyUri('JBSWY3DPEHPK3PXP', 'user@example.com', 'MyApp');
 * // → otpauth://totp/MyApp:user%40example.com?secret=JBSWY3...&issuer=MyApp&digits=6&period=30
 */
export declare function totpKeyUri(secretBase32: string, account: string, issuer: string, options?: Pick<TOTPOptions, 'digits' | 'period'>): string;
/**
 * Generate an HOTP code for a given counter value.
 * HOTP is the building block for TOTP.
 *
 * @param secretBase32 - The shared secret in base32 encoding
 * @param counter      - The counter value (integer, ≥ 0)
 * @param options      - digits (default: 6)
 */
export declare function generateHOTP(secretBase32: string, counter: number, options?: HOTPOptions): Promise<string>;
/**
 * Generate the current TOTP code.
 *
 * @param secretBase32 - The shared secret in base32 encoding
 * @param options      - digits, period (seconds), timestamp override
 */
export declare function generateTOTP(secretBase32: string, options?: TOTPOptions): Promise<string>;
/**
 * Verify a TOTP code entered by the user.
 * Checks the current window plus ±skew windows to handle clock drift.
 *
 * Returns a result object with validity, the matched counter, and remaining
 * seconds in the current window.
 */
export declare function verifyTOTP(code: string, secretBase32: string, options?: TOTPOptions & {
    skew?: number;
}): Promise<TOTPVerifyResult>;
/** Encode bytes to base32 (RFC 4648, no padding) */
export declare function toBase32(bytes: Uint8Array): string;
/** Decode a base32 string to bytes */
export declare function fromBase32(base32: string): Uint8Array;
//# sourceMappingURL=otp.d.ts.map