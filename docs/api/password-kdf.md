---
title: Password KDF
description: Derive strong encryption keys from human passwords with scrypt or PBKDF2.
---

# Password-Based Key Derivation

Derives a strong encryption key from a human password. Uses **scrypt** in Node.js (memory-hard, GPU-resistant) or **PBKDF2** in browsers/edge.

```ts
import { deriveKeyFromPassword } from '{{ site.npm_package }}';

// Derive a key from a password (generates a random salt)
const { keyHex, saltHex, algorithm, params } = await deriveKeyFromPassword(
  'my-secure-passphrase',
  'user:vault',
  { algorithm: 'scrypt' } // default in Node; use 'pbkdf2' for browser/edge
);

// Encrypt the user's data with their password-derived key
const userEnc = new EncryptixClient({ key: keyHex });
const encrypted = await userEnc.encrypt(sensitiveData, 'user:vault');
```

## Re-deriving the key

Store `saltHex` (and `algorithm`/`params`) alongside the encrypted data. Re-derive with the same salt to decrypt later.

```ts
const { keyHex: derivedKey } = await deriveKeyFromPassword(
  userPassword,
  'user:vault',
  { algorithm, ...params, saltHex }
);
const decEnc = new EncryptixClient({ key: derivedKey });
const decrypted = await decEnc.decrypt(encrypted, 'user:vault');
```

```ts
deriveKeyFromPassword(
  password: string,
  purpose: string,
  options?: DeriveKeyFromPasswordOptions
): Promise<DerivedPasswordKey>
// → { keyHex, saltHex, algorithm, params }
```

<div class="callout callout-warning"><span class="ic">🧂</span><p><strong>Always store the <code>saltHex</code>.</strong> Without the exact same salt (and algorithm/params) you cannot re-derive the same key, and the data becomes unrecoverable. Salt is not secret — store it next to the ciphertext.</p></div>
