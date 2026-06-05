"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateTOTPSecret = generateTOTPSecret;
exports.totpKeyUri = totpKeyUri;
exports.generateHOTP = generateHOTP;
exports.generateTOTP = generateTOTP;
exports.verifyTOTP = verifyTOTP;
exports.toBase32 = toBase32;
exports.fromBase32 = fromBase32;
const env_js_1 = require("../utils/env.js");
const errors_js_1 = require("../utils/errors.js");
// ─── Constants ────────────────────────────────────────────────────────────────
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const DEFAULT_DIGITS = 6;
const DEFAULT_WINDOW = 30; // seconds
const DEFAULT_SKEW = 1; // ±1 window of clock skew tolerance
// ─── Secret Generation ────────────────────────────────────────────────────────
/**
 * Generate a cryptographically random TOTP secret.
 * Returns a base32-encoded string (the standard format for authenticator apps).
 *
 * @param bytes - Secret length in bytes. 20 bytes = 160 bits (RFC minimum).
 */
function generateTOTPSecret(bytes = 20) {
    const random = (0, env_js_1.getCrypto)().getRandomValues(new Uint8Array(bytes));
    return toBase32(random);
}
/**
 * Generate a TOTP key URI for QR code generation.
 * The URI can be encoded into a QR code and scanned by any authenticator app.
 *
 * @example
 * const uri = totpKeyUri('JBSWY3DPEHPK3PXP', 'user@example.com', 'MyApp');
 * // → otpauth://totp/MyApp:user%40example.com?secret=JBSWY3...&issuer=MyApp&digits=6&period=30
 */
function totpKeyUri(secretBase32, account, issuer, options = {}) {
    const digits = options.digits ?? DEFAULT_DIGITS;
    const period = options.period ?? DEFAULT_WINDOW;
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
    return `otpauth://totp/${label}?secret=${secretBase32.toUpperCase()}&issuer=${encodeURIComponent(issuer)}&digits=${digits}&period=${period}`;
}
// ─── HOTP ─────────────────────────────────────────────────────────────────────
/**
 * Generate an HOTP code for a given counter value.
 * HOTP is the building block for TOTP.
 *
 * @param secretBase32 - The shared secret in base32 encoding
 * @param counter      - The counter value (integer, ≥ 0)
 * @param options      - digits (default: 6)
 */
async function generateHOTP(secretBase32, counter, options = {}) {
    const digits = options.digits ?? DEFAULT_DIGITS;
    const secretBytes = fromBase32(secretBase32);
    const subtle = (0, env_js_1.getCrypto)().subtle;
    const key = await subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    // Pack counter as 8-byte big-endian integer
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);
    const hmac = new Uint8Array(await subtle.sign('HMAC', key, counterBuf));
    // Dynamic truncation per RFC 4226
    const offset = hmac[19] & 0x0f;
    const code = (((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)) % Math.pow(10, digits);
    return String(code).padStart(digits, '0');
}
// ─── TOTP ─────────────────────────────────────────────────────────────────────
/**
 * Generate the current TOTP code.
 *
 * @param secretBase32 - The shared secret in base32 encoding
 * @param options      - digits, period (seconds), timestamp override
 */
async function generateTOTP(secretBase32, options = {}) {
    const period = options.period ?? DEFAULT_WINDOW;
    const timestamp = options.timestamp ?? Date.now();
    const counter = Math.floor(timestamp / 1000 / period);
    return generateHOTP(secretBase32, counter, options);
}
/**
 * Verify a TOTP code entered by the user.
 * Checks the current window plus ±skew windows to handle clock drift.
 *
 * Returns a result object with validity, the matched counter, and remaining
 * seconds in the current window.
 */
async function verifyTOTP(code, secretBase32, options = {}) {
    const period = options.period ?? DEFAULT_WINDOW;
    const skew = options.skew ?? DEFAULT_SKEW;
    const timestamp = options.timestamp ?? Date.now();
    const currentCounter = Math.floor(timestamp / 1000 / period);
    // Normalise code: strip spaces, ensure it is digits only
    const normalised = code.replace(/\s/g, '');
    if (!/^\d+$/.test(normalised)) {
        return { valid: false, delta: null, remainingSeconds: 0 };
    }
    for (let delta = -skew; delta <= skew; delta++) {
        const expected = await generateHOTP(secretBase32, currentCounter + delta, options);
        if (constantTimeStringEqual(normalised, expected)) {
            const elapsed = (timestamp / 1000) % period;
            const remainingSeconds = Math.ceil(period - elapsed);
            return { valid: true, delta, remainingSeconds };
        }
    }
    return { valid: false, delta: null, remainingSeconds: 0 };
}
// ─── Base32 ──────────────────────────────────────────────────────────────────
/** Encode bytes to base32 (RFC 4648, no padding) */
function toBase32(bytes) {
    let bits = 0;
    let value = 0;
    let output = '';
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
    }
    return output;
}
/** Decode a base32 string to bytes */
function fromBase32(base32) {
    const input = base32.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
    let bits = 0;
    let value = 0;
    const output = [];
    for (const char of input) {
        const idx = BASE32_ALPHABET.indexOf(char);
        if (idx === -1) {
            throw new errors_js_1.EncryptixError('CODEC_ERROR', `Invalid base32 character: '${char}'`);
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(output);
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function constantTimeStringEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}
//# sourceMappingURL=otp.js.map