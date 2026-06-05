/**
 * RSA-PSS Digital Signatures
 *
 * RSA-PSS (Probabilistic Signature Scheme) is the modern RSA signing standard.
 * It is intentionally separate from RSA-OAEP (encryption) — the same key pair
 * should NOT be used for both signing and encryption.
 *
 * Use ECDSA for new code when possible — RSA-PSS is here for interoperability
 * with systems that require RSA signatures (older APIs, FIPS environments, etc).
 *
 * Why RSA-PSS over PKCS1v1.5?
 *   - PSS has a formal security proof; PKCS1v1.5 does not.
 *   - PSS is randomized (different signature each time); PKCS1v1.5 is deterministic.
 *   - PKCS1v1.5 is vulnerable to certain padding oracle attacks.
 */
import type { RSAKeyPair, Encoding } from '../types/index.js';
/**
 * Generate an RSA-PSS key pair for signing.
 * Use a separate key pair from your RSA-OAEP encryption keys.
 */
export declare function generateRSAPSSKeyPair(modulusLength?: 2048 | 4096, hash?: 'SHA-256' | 'SHA-384' | 'SHA-512'): Promise<RSAKeyPair>;
/**
 * Sign data with an RSA-PSS private key.
 * Returns the signature as base64 (default), base64url, or hex.
 */
export declare function rsaPssSign(data: string | Uint8Array, privateKeyPEM: string, hash?: 'SHA-256' | 'SHA-384' | 'SHA-512', encoding?: Encoding): Promise<string>;
/**
 * Verify an RSA-PSS signature.
 * Returns true if valid, false otherwise. Never throws on invalid signatures.
 */
export declare function rsaPssVerify(data: string | Uint8Array, signature: string, publicKeyPEM: string, hash?: 'SHA-256' | 'SHA-384' | 'SHA-512', encoding?: Encoding): Promise<boolean>;
//# sourceMappingURL=rsa-sign.d.ts.map