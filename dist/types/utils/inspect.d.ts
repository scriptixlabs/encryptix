/**
 * Payload Inspection
 *
 * Read the metadata header of an encrypted payload without decrypting it.
 * Useful for debugging, routing, and key-version migration checks.
 *
 * Works on:
 *   - Symmetric payloads (encrypt/decrypt)
 *   - Deterministic payloads (encryptDeterministic)
 *   - Streaming headers (encryptStream)
 *
 * Does NOT work on:
 *   - Signed tokens (different format — use inspectToken instead)
 *   - Envelope payloads (JSON format — inspect the object directly)
 */
import type { Encoding, PayloadInspection, StreamHeaderInspection } from '../types/index.js';
/**
 * Inspect the metadata of a symmetric encrypted payload without decrypting.
 *
 * Returns algorithm, key version, payload version, and size estimate.
 * Throws INVALID_PAYLOAD if the payload is too short or malformed.
 *
 * @example
 * const info = inspectPayload(payload);
 * console.log(info.algorithm);    // 'aes-256-gcm'
 * console.log(info.keyVersion);   // 1
 * console.log(info.isDetPolicy);  // false
 */
export declare function inspectPayload(payload: string, encoding?: Encoding): PayloadInspection;
/**
 * Inspect the header of an encrypted stream (output of encryptStream).
 * Reads only the first 22 bytes — does not buffer the whole stream.
 */
export declare function inspectStreamHeader(headerBytes: Uint8Array): StreamHeaderInspection;
/**
 * Inspect a signed token's metadata without verifying the signature.
 * Useful to read `purpose`, `exp`, `iat` before deciding whether to verify.
 *
 * ⚠️ The returned data is NOT verified — do not trust it for authorization.
 *    Use verify() for that. This is for routing/debugging only.
 */
export declare function inspectToken(token: string): {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    isExpired: boolean;
    remainingTtl: number | null;
    encoding: 'base64url';
};
//# sourceMappingURL=inspect.d.ts.map