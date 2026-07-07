---
title: Core Concepts
description: Purpose scoping, the zero-dependency model, and the on-the-wire payload layout.
---

# Core Concepts

## Purpose scoping

Every operation takes a `purpose` string. It's included in the payload's AAD (Additional Authenticated Data) **and** in the HKDF key derivation info. **Decrypting with the wrong purpose always fails — even with the correct master key.**

```ts
await enc.encrypt(cardNumber, 'payment:card');
await enc.encrypt(sessionToken, 'auth:session');
await enc.encrypt(userEmail, 'user:pii:email');
// Each of these uses a completely separate derived key
```

Treat purpose strings as **security boundaries**. A value encrypted for `auth:session` can never be decrypted (or misused) as `payment:card`. A common convention is `domain:subdomain:field`.

## Zero dependencies

Everything uses the Web Crypto API (`globalThis.crypto.subtle`), available natively in Node 18+, all modern browsers, and edge runtimes. The only exceptions are **ChaCha20-Poly1305** and **scrypt**, which use Node's native `crypto` module.

This means no supply-chain surface, a tiny footprint, and identical behavior across environments.

## AEAD everywhere

All symmetric ciphers are **authenticated** (AEAD): AES-256-GCM, ChaCha20-Poly1305, and AES-SIV all produce an authentication tag that's verified on decrypt. There is no unauthenticated mode — tampering is always detected and surfaced as a [`DECRYPTION_FAILED`]({{ '/guide/error-handling/' | relative_url }}) error.

## Payload binary layout

Payloads are compact, versioned binary structures (then encoded per your `encoding` setting):

```
Symmetric payload:
  [1B version][1B algo_id][2B key_version][12B iv][16B tag][N bytes ciphertext]

Deterministic (AES-SIV):
  [1B version][1B algo_id=0x03][16B SIV][N bytes ciphertext]

Streaming chunks:
  Header: [4B magic "ENCX"][1B version][1B algo][12B stream_nonce][4B chunk_size]
  Chunk:  [4B index][12B iv][16B tag][N bytes ciphertext]
```

The embedded `version` and `key_version` are what enable [key rotation]({{ '/api/key-management/' | relative_url }}) with backward-compatible payloads. You can inspect any payload's header without the key using the [inspection utilities]({{ '/api/utilities/' | relative_url }}).
