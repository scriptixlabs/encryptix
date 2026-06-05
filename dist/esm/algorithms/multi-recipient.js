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
import { getCrypto, encode, bytesToHex, bytesToBase64, base64ToBytes } from '../utils/env.js';
import { aesEncrypt, aesDecrypt } from './aes-gcm.js';
import { EncryptixError } from '../utils/errors.js';
const ENVELOPE_VERSION = 1;
// ─── Encrypt ─────────────────────────────────────────────────────────────────
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
export async function multiRecipientEncrypt(plaintext, recipients, namespace, hashAlg, options = {}) {
    if (!recipients.length) {
        throw new EncryptixError('ENVELOPE_ERROR', 'At least one recipient is required.');
    }
    const dataAlgorithm = options.dataAlgorithm ?? 'aes-256-gcm';
    const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    // 1. Generate a fresh random DEK
    const dek = getCrypto().getRandomValues(new Uint8Array(32));
    const dekHex = bytesToHex(dek);
    // 2. Encrypt plaintext with the DEK
    // We use a fixed purpose for the DEK encryption — the per-recipient
    // wrapping provides the actual access control
    const ciphertextBytes = await aesEncrypt(plaintext, dekHex, 'multi-recipient:data', namespace, hashAlg, aad);
    // 3. Wrap the DEK for each recipient using RSA-OAEP
    const subtle = getCrypto().subtle;
    const wrappedRecipients = await Promise.all(recipients.map(async (recipient) => {
        let publicKey;
        try {
            publicKey = await subtle.importKey('spki', fromPEM(recipient.publicKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
        }
        catch (err) {
            throw new EncryptixError('ENVELOPE_ERROR', `Failed to import public key for recipient '${recipient.id}'.`, err);
        }
        let wrappedDek;
        try {
            wrappedDek = await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, dek);
        }
        catch (err) {
            throw new EncryptixError('ENVELOPE_ERROR', `Failed to wrap DEK for recipient '${recipient.id}'.`, err);
        }
        return {
            id: recipient.id,
            wrappedDek: bytesToBase64(new Uint8Array(wrappedDek), false),
        };
    }));
    return {
        version: ENVELOPE_VERSION,
        recipients: wrappedRecipients,
        ciphertext: bytesToBase64(ciphertextBytes, false),
        dataAlgorithm,
    };
}
// ─── Decrypt ─────────────────────────────────────────────────────────────────
/**
 * Decrypt a multi-recipient envelope using your private key.
 *
 * @param envelope      - The envelope produced by multiRecipientEncrypt
 * @param recipientId   - Your recipient ID (must match one in envelope.recipients)
 * @param privateKeyPEM - Your RSA private key (PEM)
 */
export async function multiRecipientDecrypt(envelope, recipientId, privateKeyPEM, namespace, hashAlg, options = {}) {
    if (envelope.version !== ENVELOPE_VERSION) {
        throw new EncryptixError('UNSUPPORTED_VERSION', `Unsupported envelope version: ${envelope.version}`);
    }
    const recipient = envelope.recipients.find(r => r.id === recipientId);
    if (!recipient) {
        throw new EncryptixError('ENVELOPE_ERROR', `Recipient '${recipientId}' not found in envelope. Available: [${envelope.recipients.map(r => r.id).join(', ')}]`);
    }
    const aad = options.aad ? (typeof options.aad === 'string' ? encode(options.aad) : options.aad) : undefined;
    const subtle = getCrypto().subtle;
    // 1. Import private key
    let privateKey;
    try {
        privateKey = await subtle.importKey('pkcs8', fromPEM(privateKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }
    catch (err) {
        throw new EncryptixError('ENVELOPE_ERROR', 'Failed to import RSA private key.', err);
    }
    // 2. Unwrap the DEK
    const wrappedDekBytes = base64ToBytes(recipient.wrappedDek);
    let dekBytes;
    try {
        dekBytes = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, wrappedDekBytes);
    }
    catch (err) {
        throw new EncryptixError('ENVELOPE_ERROR', 'Failed to unwrap DEK. Ensure you are using the correct private key for this recipient.', err);
    }
    const dekHex = bytesToHex(new Uint8Array(dekBytes));
    // 3. Decrypt the data with the DEK
    const ciphertextBytes = base64ToBytes(envelope.ciphertext);
    return aesDecrypt(ciphertextBytes, dekHex, 'multi-recipient:data', namespace, hashAlg, aad);
}
/**
 * Add a new recipient to an existing envelope.
 * Requires any existing recipient's private key to unwrap the DEK,
 * then re-wraps it for the new recipient.
 *
 * The ciphertext is NOT re-encrypted — only the DEK wrapping changes.
 */
export async function addRecipient(envelope, existingRecipientId, existingPrivateKeyPEM, newRecipient) {
    const subtle = getCrypto().subtle;
    // Unwrap DEK with existing recipient
    const existing = envelope.recipients.find(r => r.id === existingRecipientId);
    if (!existing) {
        throw new EncryptixError('ENVELOPE_ERROR', `Recipient '${existingRecipientId}' not found.`);
    }
    let privateKey;
    try {
        privateKey = await subtle.importKey('pkcs8', fromPEM(existingPrivateKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }
    catch (err) {
        throw new EncryptixError('ENVELOPE_ERROR', 'Failed to import existing private key.', err);
    }
    const dekBytes = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, base64ToBytes(existing.wrappedDek)));
    // Wrap DEK for new recipient
    let newPublicKey;
    try {
        newPublicKey = await subtle.importKey('spki', fromPEM(newRecipient.publicKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    }
    catch (err) {
        throw new EncryptixError('ENVELOPE_ERROR', `Failed to import new recipient '${newRecipient.id}' public key.`, err);
    }
    const newWrappedDek = bytesToBase64(new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, newPublicKey, dekBytes)), false);
    return {
        ...envelope,
        recipients: [
            ...envelope.recipients,
            { id: newRecipient.id, wrappedDek: newWrappedDek },
        ],
    };
}
/** Remove a recipient from an envelope (does not re-encrypt data). */
export function removeRecipient(envelope, recipientId) {
    if (!envelope.recipients.find(r => r.id === recipientId)) {
        throw new EncryptixError('ENVELOPE_ERROR', `Recipient '${recipientId}' not found.`);
    }
    return {
        ...envelope,
        recipients: envelope.recipients.filter(r => r.id !== recipientId),
    };
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
function fromPEM(pem) {
    const base64 = pem
        .replace(/-----BEGIN [A-Z ]+-----/, '')
        .replace(/-----END [A-Z ]+-----/, '')
        .replace(/\s+/g, '');
    return base64ToBytes(base64).buffer;
}
//# sourceMappingURL=multi-recipient.js.map