/**
 * Batch Encryption / Decryption
 *
 * Encrypt or decrypt arrays of values efficiently using Promise.all —
 * all operations run in parallel, each with its own random IV.
 *
 * Useful for:
 *   - Encrypting a column of database records before storage
 *   - Decrypting a page of search results
 *   - Encrypting multiple fields of a single record atomically
 *
 * Each item is independently encrypted — a failure in one item
 * does not affect others (partial results surface via BatchResult).
 */
import type { EncryptOptions, DecryptOptions, BatchResult, BatchEncryptItem } from '../types/index.js';
type EncryptFn = (plaintext: string, purpose: string, options?: EncryptOptions) => Promise<string>;
type DecryptFn = (payload: string, purpose: string, options?: DecryptOptions) => Promise<string>;
/**
 * Encrypt an array of strings, all with the same purpose.
 * Returns encrypted payloads in the same order as input.
 *
 * @example
 * const encrypted = await encryptBatch(enc.encrypt.bind(enc), emails, 'user:email');
 */
export declare function encryptBatch(encryptFn: EncryptFn, items: string[], purpose: string, options?: EncryptOptions): Promise<string[]>;
/**
 * Encrypt an array of strings, each with its own purpose.
 * Useful when encrypting heterogeneous fields in one shot.
 *
 * @example
 * const encrypted = await encryptBatchMixed(enc.encrypt.bind(enc), [
 *   { value: user.email,  purpose: 'user:email'  },
 *   { value: user.phone,  purpose: 'user:phone'  },
 *   { value: user.ssn,    purpose: 'user:ssn'    },
 * ]);
 */
export declare function encryptBatchMixed(encryptFn: EncryptFn, items: BatchEncryptItem[]): Promise<string[]>;
/**
 * Decrypt an array of encrypted payloads, all with the same purpose.
 * Returns plaintext values in the same order as input.
 *
 * @example
 * const decrypted = await decryptBatch(enc.decrypt.bind(enc), encryptedEmails, 'user:email');
 */
export declare function decryptBatch(decryptFn: DecryptFn, payloads: string[], purpose: string, options?: DecryptOptions): Promise<string[]>;
/**
 * Decrypt an array of payloads with their individual purposes.
 *
 * @example
 * const decrypted = await decryptBatchMixed(enc.decrypt.bind(enc), [
 *   { payload: encEmail,  purpose: 'user:email' },
 *   { payload: encPhone,  purpose: 'user:phone' },
 * ]);
 */
export declare function decryptBatchMixed(decryptFn: DecryptFn, items: {
    payload: string;
    purpose: string;
    options?: DecryptOptions;
}[]): Promise<string[]>;
/**
 * Encrypt a batch, collecting per-item errors instead of throwing.
 * Returns BatchResult[] so callers can handle partial failures.
 *
 * @example
 * const results = await encryptBatchSafe(enc.encrypt.bind(enc), items, 'user:email');
 * const failed = results.filter(r => !r.ok);
 */
export declare function encryptBatchSafe(encryptFn: EncryptFn, items: string[], purpose: string, options?: EncryptOptions): Promise<BatchResult<string>[]>;
/**
 * Decrypt a batch, collecting per-item errors instead of throwing.
 * Useful when processing stored records where some may be corrupt or rotated.
 */
export declare function decryptBatchSafe(decryptFn: DecryptFn, payloads: string[], purpose: string, options?: DecryptOptions): Promise<BatchResult<string>[]>;
export {};
//# sourceMappingURL=batch.d.ts.map