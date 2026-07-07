---
title: Symmetric Encryption
description: AES-256-GCM / ChaCha20-Poly1305 encrypt & decrypt, AAD, TTL, and object encryption.
---

# Symmetric Encryption

Authenticated encryption with AES-256-GCM (default, works everywhere) or ChaCha20-Poly1305 (Node.js). Every operation is [purpose-scoped]({{ '/guide/core-concepts/' | relative_url }}).

## encrypt / decrypt

```ts
// AES-256-GCM (default — works everywhere)
const payload = await enc.encrypt('secret', 'my:purpose');
const plain   = await enc.decrypt(payload, 'my:purpose');

// ChaCha20-Poly1305 (Node.js only)
const enc2 = new EncryptixClient({ algorithm: 'chacha20-poly1305' });
const payload2 = await enc2.encrypt('secret', 'my:purpose');
```

```ts
encrypt(plaintext: string, purpose: string, options?: EncryptOptions): Promise<string>
decrypt(payload: string, purpose: string, options?: DecryptOptions): Promise<string>
```

## Additional authenticated data (AAD)

Bind a ciphertext to a specific user, request, or tenant. The same `aad` must be supplied on decrypt or it fails.

```ts
const payload = await enc.encrypt('data', 'auth:token', { aad: userId });
await enc.decrypt(payload, 'auth:token', { aad: userId });
```

## Time-to-live (TTL)

The expiry is embedded in the AAD, so it **cannot be stripped** without breaking authentication.

```ts
// Payload auto-expires after N seconds
const payload = await enc.encrypt('data', 'auth:token', { ttlSeconds: 3600 });
```

## Object encryption

Encrypts any JSON-serializable value. Expiry is embedded inside the ciphertext and verified transparently on decrypt — no extra parameters needed.

```ts
const payload = await enc.encryptObject(
  { userId: '123', role: 'admin' },
  'user:session',
  { ttlSeconds: 3600 }
);

// Decrypts AND checks expiry automatically
const session = await enc.decryptObject<{ userId: string; role: string }>(
  payload,
  'user:session'
);
// Throws EncryptixError { code: 'PAYLOAD_EXPIRED' } if expired
```

```ts
encryptObject<T>(value: T, purpose: string, options?: EncryptObjectOptions): Promise<string>
decryptObject<T>(payload: string, purpose: string, options?: DecryptObjectOptions): Promise<T>
```

<div class="callout callout-info"><span class="ic">ℹ️</span><p>Both ciphers are AEAD — a tampered payload, wrong key, or wrong purpose always throws <code>DECRYPTION_FAILED</code>. See <a href="{{ '/guide/error-handling/' | relative_url }}">Error Handling</a>.</p></div>
