/**
 * ECDH Key Agreement + ECDSA Digital Signatures
 *
 * ECDH (Elliptic Curve Diffie-Hellman):
 *   Two parties each generate an EC key pair and derive the same shared
 *   secret without ever transmitting it. The shared secret is then fed
 *   into HKDF to produce a symmetric encryption key.
 *
 *   Use case: end-to-end encrypted messaging, forward secrecy, key exchange
 *   without a pre-shared key.
 *
 * ECDSA (Elliptic Curve Digital Signature Algorithm):
 *   Sign data with a private key; anyone with the public key can verify.
 *   Unlike HMAC, verification does not require the signing key.
 *
 *   Use case: document signing, webhook authenticity, audit logs, JWT-style
 *   tokens where the verifier is untrusted (e.g. a client).
 *
 * Both use NIST P-256 (secp256r1) by default — universally available via
 * Web Crypto, hardware-accelerated on most platforms.
 */
import type { ECCurve, ECKeyPair, Encoding } from '../types/index.js';
/**
 * Generate an ECDH key pair for key agreement.
 * Returns PEM-encoded public/private keys plus raw JWK for storage.
 */
export declare function generateECDHKeyPair(curve?: ECCurve): Promise<ECKeyPair>;
/**
 * Derive a shared secret from your private key and the other party's public key.
 * Returns a 32-byte (256-bit) hex string suitable for use as a master key.
 *
 * Both parties independently call this with swapped keys and get the same result.
 *
 * @example
 * // Alice:
 * const aliceKeys = await generateECDHKeyPair();
 * const sharedKey = await deriveSharedSecret(aliceKeys.privateKey, bobPublicKeyPEM);
 * const enc = new EncryptixClient({ key: sharedKey });
 *
 * // Bob (same result):
 * const bobKeys = await generateECDHKeyPair();
 * const sharedKey = await deriveSharedSecret(bobKeys.privateKey, alicePublicKeyPEM);
 */
export declare function deriveSharedSecret(privateKeyPEM: string, peerPublicKeyPEM: string, curve?: ECCurve, outputLength?: number): Promise<string>;
/**
 * Generate an ECDSA key pair for signing and verification.
 */
export declare function generateECDSAKeyPair(curve?: ECCurve): Promise<ECKeyPair>;
/**
 * Sign data with an ECDSA private key.
 * Returns a DER-encoded signature as base64 (default) or hex.
 *
 * @param data       - The message to sign (string or bytes)
 * @param privateKeyPEM - PEM-encoded PKCS8 private key
 */
export declare function ecdsaSign(data: string | Uint8Array, privateKeyPEM: string, curve?: ECCurve, encoding?: Encoding): Promise<string>;
/**
 * Verify an ECDSA signature.
 * Returns true if the signature is valid, false otherwise.
 * Never throws on invalid signatures — only on key import errors.
 */
export declare function ecdsaVerify(data: string | Uint8Array, signature: string, publicKeyPEM: string, curve?: ECCurve, encoding?: Encoding): Promise<boolean>;
//# sourceMappingURL=ecdh.d.ts.map