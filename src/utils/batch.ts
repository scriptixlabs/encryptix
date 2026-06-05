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

import { EncryptixError } from './errors.js';
import type { EncryptOptions, DecryptOptions, BatchResult, BatchEncryptItem } from '../types/index.js';

type EncryptFn = (plaintext: string, purpose: string, options?: EncryptOptions) => Promise<string>;
type DecryptFn = (payload: string, purpose: string, options?: DecryptOptions) => Promise<string>;

// ─── Batch Encrypt ────────────────────────────────────────────────────────────

/**
 * Encrypt an array of strings, all with the same purpose.
 * Returns encrypted payloads in the same order as input.
 *
 * @example
 * const encrypted = await encryptBatch(enc.encrypt.bind(enc), emails, 'user:email');
 */
export async function encryptBatch(
  encryptFn: EncryptFn,
  items: string[],
  purpose: string,
  options?: EncryptOptions,
): Promise<string[]> {
  if (!items.length) return [];
  const results = await Promise.all(
    items.map(item => encryptFn(item, purpose, options)),
  );
  return results;
}

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
export async function encryptBatchMixed(
  encryptFn: EncryptFn,
  items: BatchEncryptItem[],
): Promise<string[]> {
  if (!items.length) return [];
  return Promise.all(
    items.map(({ value, purpose, options }) => encryptFn(value, purpose, options)),
  );
}

/**
 * Decrypt an array of encrypted payloads, all with the same purpose.
 * Returns plaintext values in the same order as input.
 *
 * @example
 * const decrypted = await decryptBatch(enc.decrypt.bind(enc), encryptedEmails, 'user:email');
 */
export async function decryptBatch(
  decryptFn: DecryptFn,
  payloads: string[],
  purpose: string,
  options?: DecryptOptions,
): Promise<string[]> {
  if (!payloads.length) return [];
  return Promise.all(
    payloads.map(payload => decryptFn(payload, purpose, options)),
  );
}

/**
 * Decrypt an array of payloads with their individual purposes.
 *
 * @example
 * const decrypted = await decryptBatchMixed(enc.decrypt.bind(enc), [
 *   { payload: encEmail,  purpose: 'user:email' },
 *   { payload: encPhone,  purpose: 'user:phone' },
 * ]);
 */
export async function decryptBatchMixed(
  decryptFn: DecryptFn,
  items: { payload: string; purpose: string; options?: DecryptOptions }[],
): Promise<string[]> {
  if (!items.length) return [];
  return Promise.all(
    items.map(({ payload, purpose, options }) => decryptFn(payload, purpose, options)),
  );
}

// ─── Safe Batch (partial failures) ───────────────────────────────────────────

/**
 * Encrypt a batch, collecting per-item errors instead of throwing.
 * Returns BatchResult[] so callers can handle partial failures.
 *
 * @example
 * const results = await encryptBatchSafe(enc.encrypt.bind(enc), items, 'user:email');
 * const failed = results.filter(r => !r.ok);
 */
export async function encryptBatchSafe(
  encryptFn: EncryptFn,
  items: string[],
  purpose: string,
  options?: EncryptOptions,
): Promise<BatchResult<string>[]> {
  return Promise.all(
    items.map(async (item, index): Promise<BatchResult<string>> => {
      try {
        const value = await encryptFn(item, purpose, options);
        return { ok: true, value, index };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof EncryptixError ? err : new EncryptixError('ENCRYPTION_FAILED', String(err), err),
          index,
        };
      }
    }),
  );
}

/**
 * Decrypt a batch, collecting per-item errors instead of throwing.
 * Useful when processing stored records where some may be corrupt or rotated.
 */
export async function decryptBatchSafe(
  decryptFn: DecryptFn,
  payloads: string[],
  purpose: string,
  options?: DecryptOptions,
): Promise<BatchResult<string>[]> {
  return Promise.all(
    payloads.map(async (payload, index): Promise<BatchResult<string>> => {
      try {
        const value = await decryptFn(payload, purpose, options);
        return { ok: true, value, index };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof EncryptixError ? err : new EncryptixError('DECRYPTION_FAILED', String(err), err),
          index,
        };
      }
    }),
  );
}
