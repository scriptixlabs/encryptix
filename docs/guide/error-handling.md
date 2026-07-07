---
title: Error Handling
description: Every failure is an EncryptixError with a machine-readable code.
---

# Error Handling

All errors are `EncryptixError` instances with a machine-readable `code`, so you can branch on failure modes without string-matching messages.

```ts
import { EncryptixError } from '{{ site.npm_package }}';

try {
  await enc.decrypt(payload, 'wrong:purpose');
} catch (err) {
  if (err instanceof EncryptixError) {
    switch (err.code) {
      case 'DECRYPTION_FAILED':        // tampered, wrong key, or wrong purpose
      case 'INVALID_PAYLOAD':          // malformed or wrong encoding
      case 'PAYLOAD_EXPIRED':          // TTL on encryptObject expired
      case 'TOKEN_EXPIRED':            // TTL on signed token expired
      case 'TOKEN_INVALID':            // tampered signed token
      case 'UNSUPPORTED_VERSION':      // future payload version
      case 'UNSUPPORTED_ALGORITHM':    // unknown algorithm ID
      case 'INVALID_KEY':              // missing or malformed master key
      case 'KEY_NOT_FOUND':            // missing version in keychain
      case 'INVALID_PURPOSE':          // empty purpose string
      case 'RSA_KEY_ERROR':            // invalid PEM or wrong key type
      case 'ENVELOPE_ERROR':           // DEK wrap/unwrap failure
      case 'STREAM_ERROR':             // stream magic, version, or chunk auth failure
      case 'PASSWORD_KDF_FAILED':      // scrypt/PBKDF2 derivation failure
      case 'ENVIRONMENT_UNSUPPORTED':  // ChaCha20/scrypt in browser/edge
    }
  }
}
```

## Error codes

| Code | Meaning |
|---|---|
| `DECRYPTION_FAILED` | Tampered ciphertext, wrong key, or wrong purpose. |
| `INVALID_PAYLOAD` | Malformed payload or wrong encoding. |
| `PAYLOAD_EXPIRED` | TTL on `encryptObject` has passed. |
| `TOKEN_EXPIRED` | TTL on a signed token has passed. |
| `TOKEN_INVALID` | Tampered or malformed signed token. |
| `UNSUPPORTED_VERSION` | Payload from a newer library version. |
| `UNSUPPORTED_ALGORITHM` | Unknown algorithm ID in payload. |
| `INVALID_KEY` | Missing or malformed master key. |
| `KEY_NOT_FOUND` | Referenced key version missing from the keychain. |
| `INVALID_PURPOSE` | Empty purpose string. |
| `RSA_KEY_ERROR` | Invalid PEM or wrong key type. |
| `ENVELOPE_ERROR` | DEK wrap/unwrap failure. |
| `STREAM_ERROR` | Stream magic, version, or chunk-auth failure. |
| `PASSWORD_KDF_FAILED` | scrypt/PBKDF2 derivation failure. |
| `ENVIRONMENT_UNSUPPORTED` | ChaCha20/scrypt used in a browser/edge runtime. |

<div class="callout callout-info"><span class="ic">ℹ️</span><p>Token verification via <a href="{{ '/api/signed-tokens/' | relative_url }}"><code>verify()</code></a> does <strong>not</strong> throw on invalid tokens by default — it returns <code>{ valid: false, reason }</code>. Pass <code>throwOnExpiry: true</code> to throw <code>TOKEN_EXPIRED</code> instead.</p></div>
