/**
 * Multi-Recipient Envelope Encryption
 *
 * One plaintext → one ciphertext → N wrapped DEKs, one per recipient.
 * Each recipient can independently decrypt using only their own private key.
 *
 * This is the pattern used by PGP, S/MIME, and enterprise key escrow.
 *
 * Layout:
 *   {
 *     recipients: [
 *       { id: 'alice@example.com', wrappedDek: '<RSA-OAEP(DEK, alice.pub)>' },
 *       { id: 'bob@example.com',   wrappedDek: '<RSA-OAEP(DEK, bob.pub)>'  },
 *     ],
 *     ciphertext: '<AES-GCM(plaintext, DEK)>',
 *     algorithm: 'aes-256-gcm',
 *     version: 1,
 *   }
 *
 * Security properties:
 *   - DEK is never stored in plaintext — only RSA-OAEP wrapped copies
 *   - Adding/removing a recipient requires only re-wrapping the DEK
 *   - The data ciphertext never needs to be re-encrypted for key changes
 *   - Each recipient's wrappedDek is independent — compromise of one
 *     recipient's private key does not affect other recipients
 */
import type { MultiRecipientEnvelope, MultiRecipientOptions, RecipientKey, HashAlgorithm } from '../types/index.js';
/**
 * Encrypt data for multiple recipients.
 * Each recipient is identified by an `id` and their RSA public key (PEM).
 *
 * @example
 * const envelope = await multiRecipientEncrypt('sensitive data', [
 *   { id: 'alice@example.com', publicKeyPEM: alicePublicKey },
 *   { id: 'bob@example.com',   publicKeyPEM: bobPublicKey   },
 * ]);
 * // Store the envelope. Alice and Bob can each decrypt with their private key.
 */
export declare function multiRecipientEncrypt(plaintext: string, recipients: RecipientKey[], namespace: string, hashAlg: HashAlgorithm, options?: MultiRecipientOptions): Promise<MultiRecipientEnvelope>;
/**
 * Decrypt a multi-recipient envelope using your private key.
 *
 * @param envelope      - The envelope produced by multiRecipientEncrypt
 * @param recipientId   - Your recipient ID (must match one in envelope.recipients)
 * @param privateKeyPEM - Your RSA private key (PEM)
 */
export declare function multiRecipientDecrypt(envelope: MultiRecipientEnvelope, recipientId: string, privateKeyPEM: string, namespace: string, hashAlg: HashAlgorithm, options?: MultiRecipientOptions): Promise<string>;
/**
 * Add a new recipient to an existing envelope.
 * Requires any existing recipient's private key to unwrap the DEK,
 * then re-wraps it for the new recipient.
 *
 * The ciphertext is NOT re-encrypted — only the DEK wrapping changes.
 */
export declare function addRecipient(envelope: MultiRecipientEnvelope, existingRecipientId: string, existingPrivateKeyPEM: string, newRecipient: RecipientKey): Promise<MultiRecipientEnvelope>;
/** Remove a recipient from an envelope (does not re-encrypt data). */
export declare function removeRecipient(envelope: MultiRecipientEnvelope, recipientId: string): MultiRecipientEnvelope;
//# sourceMappingURL=multi-recipient.d.ts.map