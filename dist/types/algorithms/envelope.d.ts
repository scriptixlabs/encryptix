/**
 * Envelope Encryption for @ppabari/encryptix
 *
 * Pattern:
 *   1. Generate a random 256-bit Data Encryption Key (DEK) per payload
 *   2. Encrypt the actual data with the DEK (AES-256-GCM or ChaCha20)
 *   3. Wrap the DEK with the Key Encryption Key (KEK) using AES-KW (RFC 3394)
 *   4. Store: { wrappedDek, ciphertext, metadata }
 *
 * Benefits:
 *   - Revoking access to ONE record: re-wrap or discard its DEK
 *   - Rotating the KEK: re-wrap all DEKs without re-encrypting data
 *   - Multiple recipients: wrap the same DEK with each recipient's KEK
 *   - The KEK (your master key) never directly touches the data
 */
import type { EnvelopePayload, EnvelopeEncryptOptions, EnvelopeDecryptOptions, HashAlgorithm } from '../types/index.js';
export declare function envelopeEncrypt(plaintext: string, masterKeyHex: string, purpose: string, namespace: string, hashAlg: HashAlgorithm, options?: EnvelopeEncryptOptions): Promise<EnvelopePayload>;
export declare function envelopeDecrypt(envelope: EnvelopePayload, masterKeyHex: string, purpose: string, namespace: string, hashAlg: HashAlgorithm, options?: EnvelopeDecryptOptions): Promise<string>;
//# sourceMappingURL=envelope.d.ts.map