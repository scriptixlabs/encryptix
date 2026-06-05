/**
 * Encoding / Codec Utilities
 *
 * - Base32 encode/decode (RFC 4648) — needed for TOTP secrets and human-readable keys
 * - Constant-time base64 — timing-safe encode/decode
 * - safeCompare — constant-time comparison for tokens, MACs, signatures
 * - Encoding conversion helpers (hex ↔ base64 ↔ base64url ↔ bytes)
 */
/**
 * Encode bytes to a base32 string (RFC 4648, no padding).
 */
export declare function base32Encode(bytes: Uint8Array): string;
/**
 * Decode a base32 string to bytes.
 * Accepts both upper and lowercase. Strips whitespace and padding.
 */
export declare function base32Decode(input: string): Uint8Array;
/** Encode bytes to a lowercase hex string. */
export declare function hexEncode(bytes: Uint8Array): string;
/** Decode a hex string to bytes. */
export declare function hexDecode(hex: string): Uint8Array;
/** Encode bytes to base64. */
export declare function base64Encode(bytes: Uint8Array): string;
/** Encode bytes to base64url (URL-safe, no padding). */
export declare function base64urlEncode(bytes: Uint8Array): string;
/** Decode a base64 or base64url string to bytes. */
export declare function base64Decode(input: string): Uint8Array;
/**
 * Convert between encodings without going through string intermediates
 * more than necessary.
 *
 * @example
 * convertEncoding('aGVsbG8=', 'base64', 'hex')  // → '68656c6c6f'
 * convertEncoding('68656c6c6f', 'hex', 'base64url') // → 'aGVsbG8'
 */
export declare function convertEncoding(input: string, from: 'hex' | 'base64' | 'base64url', to: 'hex' | 'base64' | 'base64url'): string;
/**
 * Compare two strings or byte arrays in constant time.
 * Prevents timing attacks when comparing tokens, MACs, or signatures.
 *
 * Returns true only if both values are identical.
 * The comparison always takes O(n) time where n = max(a.length, b.length),
 * regardless of where the first difference occurs.
 *
 * @example
 * // Instead of:
 * if (userToken === storedToken)  // ❌ timing leak
 *
 * // Use:
 * if (safeCompare(userToken, storedToken))  // ✅ constant-time
 */
export declare function safeCompare(a: string | Uint8Array, b: string | Uint8Array): boolean;
/** Encode a UTF-8 string to bytes. */
export declare function textEncode(text: string): Uint8Array;
/** Decode bytes to a UTF-8 string. */
export declare function textDecode(bytes: Uint8Array): string;
//# sourceMappingURL=codec.d.ts.map