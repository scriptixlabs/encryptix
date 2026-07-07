---
title: Configuration
description: EncryptixClient options and environment variables.
---

# Configuration

## Client options

```ts
const enc = new EncryptixClient({
  key: 'your-64-char-hex-key',       // or set ENCRYPTIX_KEY env var
  algorithm: 'aes-256-gcm',          // 'aes-256-gcm' | 'chacha20-poly1305'
  encoding: 'base64',                // 'base64' | 'base64url' | 'hex'
  hashAlgorithm: 'sha256',           // 'sha256' | 'sha384' | 'sha512'
  namespace: 'myapp',                // HKDF info prefix (default: 'encryptix')
  keychain: { 1: 'old-key-hex' },    // for key rotation
});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `key` | `string` | `ENCRYPTIX_KEY` env | 64-char hex master key (32 bytes). |
| `algorithm` | `'aes-256-gcm' \| 'chacha20-poly1305'` | `'aes-256-gcm'` | Symmetric cipher. ChaCha20 is Node-only. |
| `encoding` | `'base64' \| 'base64url' \| 'hex'` | `'base64'` | Output encoding for payloads. |
| `hashAlgorithm` | `'sha256' \| 'sha384' \| 'sha512'` | `'sha256'` | Used for HKDF, HMAC, and hashing. |
| `namespace` | `string` | `'encryptix'` | Prefix for HKDF `info` — isolates keys between apps. |
| `keychain` | `Record<number, string>` | — | Old key versions for [rotation]({{ '/api/key-management/' | relative_url }}). |

<div class="callout callout-tip"><span class="ic">💡</span><p><code>createEncryptix(config)</code> is a convenience factory equivalent to <code>new EncryptixClient(config)</code>.</p></div>

## Environment variables

| Variable | Description |
|---|---|
| `ENCRYPTIX_KEY` | 64-char hex master key (required unless `key` is passed to the constructor). |

Generate a key with:

```ts
import { generateMasterKey } from '{{ site.npm_package }}';
const key = generateMasterKey(); // → 64-char hex, store as ENCRYPTIX_KEY
```
