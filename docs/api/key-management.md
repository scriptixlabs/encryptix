---
title: Key Management
description: Key rotation, fingerprinting, zeroization, JWK import/export, and re-encryption.
---

# Key Management

## Key rotation

Rotate to a new master key while still decrypting payloads created with the old one — the key version is embedded in every payload.

```ts
const v1 = new EncryptixClient({ key: process.env.ENCRYPTIX_KEY });
const oldPayload = await v1.encrypt('old-secret', 'user:token');

// Rotate to a new key
const newKey = generateMasterKey(); // store as the new ENCRYPTIX_KEY
const v2 = v1.rotate(newKey);

// v2 encrypts with newKey, decrypts BOTH old and new payloads
await v2.decrypt(oldPayload, 'user:token');                            // ✅ uses v1 key automatically
await v2.decrypt(await v2.encrypt('new', 'user:token'), 'user:token'); // ✅
```

Under the hood, `rotate()` moves the current key into the `keychain` under its version so old payloads still resolve. You can also seed old versions directly via the [`keychain` config]({{ '/guide/configuration/' | relative_url }}).

```ts
rotate(newKeyHex: string): EncryptixClient
```

## Key fingerprinting

```ts
const fp = await enc.keyFingerprint();
// → { fingerprint: 'a3f9e2b1c4d5e6f7', version: 1 }
```

The fingerprint is `SHA-256(key)[0:8]` — **non-reversible and safe to log**. Use it to record which key encrypted a given payload when debugging multi-key deployments.

## Re-encryption

Migrate ciphertext from one key/purpose to another without exposing plaintext to your app logic longer than necessary.

```ts
import { reEncrypt, reEncryptBatch } from '{{ site.npm_package }}';
const migrated = await reEncrypt(oldClient, newClient, payload, 'user:token');
```

## Zeroization

Wipe sensitive key material from memory when you're done with it.

```ts
import { zeroize, zeroizeAll, withZeroize } from '{{ site.npm_package }}';

zeroize(keyBytes);              // overwrite a single buffer with zeros
zeroizeAll(dek, iv, tagBytes);  // wipe several at once

// Auto-wipe after a callback, even if it throws
await withZeroize(keyBytes, async (k) => { /* use k */ });
```

## JWK & serialization

```ts
import { exportKeyToJWK, importKeyFromJWK, serializeKey, deserializeKey } from '{{ site.npm_package }}';
```

| Export | Description |
|---|---|
| `exportKeyToJWK` / `importKeyFromJWK` | Convert keys to/from the JSON Web Key format. |
| `serializeKey` / `deserializeKey` | Portable string serialization of a key. |
| `createKeyMetadataStore()` | An in-memory store for tracking key versions &amp; metadata. |
| `reEncrypt` / `reEncryptBatch` | Migrate ciphertext between keys/purposes. |
