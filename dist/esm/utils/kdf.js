import { getCrypto, encode, hexToBytes } from './env.js';
/**
 * Derives a cryptographic key from a master key using HKDF (RFC 5869).
 * Uses the Web Crypto API so it works in Node 18+, browsers, and edge runtimes.
 *
 * @param masterKeyHex - 64-char hex string (32-byte master key)
 * @param purpose      - Domain-separation string (e.g. 'user:session')
 * @param namespace    - Package namespace (default: 'encryptix')
 * @param hash         - Hash algorithm for HKDF (default: 'sha-256')
 * @param length       - Output key length in bytes (default: 32)
 * @param salt         - Optional salt bytes; defaults to zero-filled
 */
export async function deriveKey(masterKeyHex, purpose, namespace = 'encryptix', hash = 'sha256', length = 32, salt) {
    const subtle = getCrypto().subtle;
    // Import the master key as raw HKDF key material
    const keyMaterial = await subtle.importKey('raw', hexToBytes(masterKeyHex), 'HKDF', false, ['deriveKey']);
    const info = encode(`${namespace}:${purpose}`);
    const effectiveSalt = salt ?? new Uint8Array(32); // zero-filled salt = no salt
    return subtle.deriveKey({
        name: 'HKDF',
        hash: hash.toUpperCase().replace('SHA', 'SHA-'), // sha256 → SHA-256
        info: info,
        salt: effectiveSalt,
    }, keyMaterial, { name: 'AES-GCM', length: length * 8 }, false, // not extractable — key never leaves the crypto layer
    ['encrypt', 'decrypt']);
}
/**
 * Derives raw key bytes (not a CryptoKey) for use with algorithms
 * that need the raw material (e.g. ChaCha20 via Node's native crypto).
 */
export async function deriveRawKey(masterKeyHex, purpose, namespace = 'encryptix', hash = 'sha256', length = 32, salt) {
    const subtle = getCrypto().subtle;
    const keyMaterial = await subtle.importKey('raw', hexToBytes(masterKeyHex), 'HKDF', false, ['deriveBits']);
    const info = encode(`${namespace}:${purpose}`);
    const effectiveSalt = salt ?? new Uint8Array(32);
    const bits = await subtle.deriveBits({
        name: 'HKDF',
        hash: hash.toUpperCase().replace('SHA', 'SHA-'),
        info: info,
        salt: effectiveSalt,
    }, keyMaterial, length * 8);
    return new Uint8Array(bits);
}
//# sourceMappingURL=kdf.js.map