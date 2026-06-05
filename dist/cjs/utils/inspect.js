"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.inspectPayload = inspectPayload;
exports.inspectStreamHeader = inspectStreamHeader;
exports.inspectToken = inspectToken;
const env_js_1 = require("./env.js");
const errors_js_1 = require("./errors.js");
// Algorithm ID → name map (must stay in sync with algo implementations)
const ALGO_MAP = {
    0x01: 'aes-256-gcm',
    0x02: 'chacha20-poly1305',
    0x03: 'aes-siv',
};
const STREAM_MAGIC = new Uint8Array([0x45, 0x4e, 0x43, 0x58]); // 'ENCX'
// ─── Symmetric Payload ───────────────────────────────────────────────────────
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
function inspectPayload(payload, encoding = 'base64') {
    let data;
    try {
        data = (0, env_js_1.decodeInput)(payload, encoding);
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Failed to decode payload for inspection.', err);
    }
    // Symmetric payload: [version 1B][algo_id 1B][key_version 2B][iv 12B][tag 16B][ciphertext N]
    // Deterministic (SIV): [version 1B][algo_id=0x03 1B][siv 16B][ciphertext N]
    if (data.length < 4) {
        throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', `Payload too short to inspect: ${data.length} bytes.`);
    }
    const payloadVersion = data[0];
    const algoId = data[1];
    const algoName = ALGO_MAP[algoId] ?? `unknown (0x${algoId.toString(16).padStart(2, '0')})`;
    const isDeterministic = algoId === 0x03;
    let keyVersion = null;
    let estimatedPlaintextBytes = null;
    if (isDeterministic) {
        // AES-SIV: [version 1B][algo_id 1B][siv 16B][ciphertext N]
        keyVersion = null; // SIV doesn't embed key version — uses current master key
        estimatedPlaintextBytes = Math.max(0, data.length - 2 - 16);
    }
    else {
        // Standard: [version 1B][algo_id 1B][key_version 2B][iv 12B][tag 16B][ciphertext N]
        if (data.length < 4) {
            throw new errors_js_1.EncryptixError('INVALID_PAYLOAD', 'Payload too short for standard format inspection.');
        }
        keyVersion = new DataView(data.buffer, data.byteOffset + 2, 2).getUint16(0, false);
        estimatedPlaintextBytes = Math.max(0, data.length - 4 - 12 - 16);
    }
    return {
        payloadVersion,
        algorithm: algoName,
        keyVersion,
        isDeterministic,
        totalBytes: data.length,
        estimatedPlaintextBytes,
        encoding,
    };
}
// ─── Stream Header ───────────────────────────────────────────────────────────
/**
 * Inspect the header of an encrypted stream (output of encryptStream).
 * Reads only the first 22 bytes — does not buffer the whole stream.
 */
function inspectStreamHeader(headerBytes) {
    if (headerBytes.length < 22) {
        throw new errors_js_1.EncryptixError('STREAM_ERROR', `Stream header too short: need 22 bytes, got ${headerBytes.length}.`);
    }
    const magic = headerBytes.slice(0, 4);
    const isValid = magic.every((b, i) => b === STREAM_MAGIC[i]);
    if (!isValid) {
        throw new errors_js_1.EncryptixError('STREAM_ERROR', 'Invalid stream magic bytes. This is not an encryptix stream.');
    }
    const version = headerBytes[4];
    const algoId = headerBytes[5];
    const chunkSize = new DataView(headerBytes.buffer, headerBytes.byteOffset + 18, 4).getUint32(0, false);
    return {
        valid: true,
        streamVersion: version,
        algorithm: ALGO_MAP[algoId] ?? `unknown (0x${algoId.toString(16)})`,
        chunkSize,
        headerBytes: 22,
    };
}
// ─── Signed Token Inspection ─────────────────────────────────────────────────
/**
 * Inspect a signed token's metadata without verifying the signature.
 * Useful to read `purpose`, `exp`, `iat` before deciding whether to verify.
 *
 * ⚠️ The returned data is NOT verified — do not trust it for authorization.
 *    Use verify() for that. This is for routing/debugging only.
 */
function inspectToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new errors_js_1.EncryptixError('TOKEN_INVALID', 'Token must have exactly 3 dot-separated parts.');
    }
    let header;
    let payload;
    try {
        const headerBytes = base64urlDecode(parts[0]);
        header = JSON.parse(new TextDecoder().decode(headerBytes));
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('TOKEN_INVALID', 'Failed to decode token header.', err);
    }
    try {
        const payloadBytes = base64urlDecode(parts[1]);
        payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    }
    catch (err) {
        throw new errors_js_1.EncryptixError('TOKEN_INVALID', 'Failed to decode token payload.', err);
    }
    const now = Math.floor(Date.now() / 1000);
    const exp = typeof payload['exp'] === 'number' ? payload['exp'] : null;
    const isExpired = exp !== null ? now > exp : false;
    const remainingTtl = exp !== null ? exp - now : null;
    return { header, payload, isExpired, remainingTtl, encoding: 'base64url' };
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function base64urlDecode(input) {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}
//# sourceMappingURL=inspect.js.map