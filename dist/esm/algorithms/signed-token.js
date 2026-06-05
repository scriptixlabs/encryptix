/**
 * Signed Tokens for @ppabari/encryptix
 *
 * A lightweight, self-contained signed token format.
 * Think: JWT without the ecosystem complexity and algorithm confusion attacks.
 *
 * Format (base64url-encoded):
 *   header.payload.signature
 *
 *   header  = base64url({ alg: 'HMAC-SHA256', ver: 1 })
 *   payload = base64url({ payload, iat, exp?, purpose })
 *   signature = HMAC-SHA256(header + '.' + payload, derived_signing_key)
 *
 * Security properties:
 *   - HMAC-SHA256 signing (no algorithm confusion — alg is fixed, not user-controlled)
 *   - Purpose binding prevents a token issued for one context being used in another
 *   - Expiry is embedded in the signed payload (can't be stripped)
 *   - Signing key is HKDF-derived from master key + purpose (isolated per token type)
 *   - Constant-time signature verification
 */
import { getCrypto, encode, hexToBytes, bytesToBase64, base64ToBytes, bytesToHex } from '../utils/env.js';
import { deriveRawKey } from '../utils/kdf.js';
import { EncryptixError } from '../utils/errors.js';
const TOKEN_VERSION = 1;
const HEADER = { alg: 'HMAC-SHA256', ver: TOKEN_VERSION };
const ENCODED_HEADER = bytesToBase64(encode(JSON.stringify(HEADER)), true);
// ─── Sign ─────────────────────────────────────────────────────────────────────
export async function signToken(payload, purpose, masterKeyHex, namespace, hashAlg, options = {}) {
    const encoding = options.encoding ?? 'base64url';
    const now = Math.floor(Date.now() / 1000);
    const tokenPayload = {
        payload,
        iat: now,
        purpose,
        ...(options.ttlSeconds !== undefined ? { exp: now + options.ttlSeconds } : {}),
    };
    const encodedPayload = bytesToBase64(encode(JSON.stringify(tokenPayload)), true);
    const signingInput = `${ENCODED_HEADER}.${encodedPayload}`;
    const signingKey = await deriveSigningKey(masterKeyHex, purpose, namespace, hashAlg);
    const signature = await computeHmac(signingInput, signingKey);
    const encodedSig = bytesToBase64(hexToBytes(signature), true);
    const token = `${signingInput}.${encodedSig}`;
    // Re-encode per requested encoding
    if (encoding === 'base64url')
        return token;
    if (encoding === 'hex')
        return bytesToHex(encode(token));
    return bytesToBase64(encode(token), false);
}
// ─── Verify ──────────────────────────────────────────────────────────────────
export async function verifyToken(token, purpose, masterKeyHex, namespace, hashAlg, options = {}) {
    const encoding = options.encoding ?? 'base64url';
    // Decode from requested encoding back to the dot-separated string
    let tokenStr;
    try {
        if (encoding === 'hex') {
            tokenStr = new TextDecoder().decode(Uint8Array.from(token.match(/.{1,2}/g).map(b => parseInt(b, 16))));
        }
        else if (encoding === 'base64') {
            tokenStr = new TextDecoder().decode(base64ToBytes(token));
        }
        else {
            tokenStr = token; // base64url — native format
        }
    }
    catch {
        return { valid: false, payload: null, reason: 'malformed' };
    }
    const parts = tokenStr.split('.');
    if (parts.length !== 3) {
        return { valid: false, payload: null, reason: 'malformed' };
    }
    const [encodedHeader, encodedPayload, encodedSig] = parts;
    // 1. Verify header
    try {
        const headerStr = new TextDecoder().decode(base64ToBytes(encodedHeader));
        const header = JSON.parse(headerStr);
        if (header.alg !== 'HMAC-SHA256' || header.ver !== TOKEN_VERSION) {
            return { valid: false, payload: null, reason: 'malformed' };
        }
    }
    catch {
        return { valid: false, payload: null, reason: 'malformed' };
    }
    // 2. Verify signature (constant-time)
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signingKey = await deriveSigningKey(masterKeyHex, purpose, namespace, hashAlg);
    const expectedSig = await computeHmac(signingInput, signingKey);
    const expectedSigBytes = hexToBytes(expectedSig);
    let providedSigBytes;
    try {
        providedSigBytes = base64ToBytes(encodedSig);
    }
    catch {
        return { valid: false, payload: null, reason: 'malformed' };
    }
    const sigValid = constantTimeEqual(expectedSigBytes, providedSigBytes);
    if (!sigValid) {
        return { valid: false, payload: null, reason: 'invalid_signature' };
    }
    // 3. Decode payload (only after signature is verified)
    let tokenPayload;
    try {
        const payloadStr = new TextDecoder().decode(base64ToBytes(encodedPayload));
        tokenPayload = JSON.parse(payloadStr);
    }
    catch {
        return { valid: false, payload: null, reason: 'malformed' };
    }
    // 4. Verify purpose binding
    if (tokenPayload.purpose !== purpose) {
        return { valid: false, payload: null, reason: 'invalid_signature' };
    }
    // 5. Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (tokenPayload.exp !== undefined) {
        const remainingTtl = tokenPayload.exp - now;
        if (remainingTtl <= 0) {
            if (options.throwOnExpiry) {
                throw new EncryptixError('TOKEN_EXPIRED', `Token expired ${Math.abs(remainingTtl)}s ago.`);
            }
            return { valid: false, payload: null, reason: 'expired', remainingTtl };
        }
        return { valid: true, payload: tokenPayload.payload, reason: 'valid', remainingTtl };
    }
    return { valid: true, payload: tokenPayload.payload, reason: 'valid' };
}
// ─── Helpers ──────────────────────────────────────────────────────────────────
async function deriveSigningKey(masterKeyHex, purpose, namespace, hashAlg) {
    return deriveRawKey(masterKeyHex, `${purpose}:signing`, namespace, hashAlg, 32);
}
async function computeHmac(message, keyBytes) {
    const subtle = getCrypto().subtle;
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await subtle.sign('HMAC', key, encode(message));
    return bytesToHex(new Uint8Array(sig));
}
function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
//# sourceMappingURL=signed-token.js.map