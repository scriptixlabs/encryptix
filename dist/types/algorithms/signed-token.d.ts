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
import type { SignTokenOptions, VerifyTokenOptions, VerifyTokenResult, HashAlgorithm } from '../types/index.js';
export declare function signToken<T>(payload: T, purpose: string, masterKeyHex: string, namespace: string, hashAlg: HashAlgorithm, options?: SignTokenOptions): Promise<string>;
export declare function verifyToken<T>(token: string, purpose: string, masterKeyHex: string, namespace: string, hashAlg: HashAlgorithm, options?: VerifyTokenOptions): Promise<VerifyTokenResult<T>>;
//# sourceMappingURL=signed-token.d.ts.map