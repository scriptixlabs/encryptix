---
title: Getting Started
description: Install encryptix and encrypt your first value in under a minute.
---

# Getting Started

`{{ site.npm_package }}` is a secure, **zero-dependency** crypto toolkit for Node.js, browsers, and edge runtimes — AES-256-GCM, ChaCha20-Poly1305, RSA, ECDH/ECDSA, AES-SIV, TOTP/HOTP, envelope encryption, streaming, signed tokens, and more.

## Installation

```bash
npm install {{ site.npm_package }}
# or
pnpm add {{ site.npm_package }}
# or
yarn add {{ site.npm_package }}
```

## Quick Start

```ts
import { EncryptixClient, generateMasterKey } from '{{ site.npm_package }}';

// One-time: generate and store your master key
const key = generateMasterKey(); // 64-char hex = 32 bytes
// → store as ENCRYPTIX_KEY in your environment

// Create a client (reads ENCRYPTIX_KEY from env automatically)
const enc = new EncryptixClient();

// Encrypt and decrypt
const payload = await enc.encrypt('user@example.com', 'user:email');
const email   = await enc.decrypt(payload, 'user:email');
```

<div class="callout callout-warning"><span class="ic">🔑</span><p><strong>Store your key safely.</strong> Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Never commit it to source control.</p></div>

## What's next

- [Core Concepts]({{ '/guide/core-concepts/' | relative_url }}) — purpose scoping, the zero-dependency model, and the payload layout.
- [Configuration]({{ '/guide/configuration/' | relative_url }}) — client options and environment variables.
- [API Overview]({{ '/api/overview/' | relative_url }}) — the full method reference.

## Runtime support

| Environment | Supported | Notes |
|---|---|---|
| Node.js | ✅ **≥ 18** | Web Crypto is global from Node 18. |
| Browsers | ✅ modern | Chrome, Edge, Firefox, Safari. |
| Deno / Bun | ✅ | Web Crypto built in. |
| Cloudflare Workers / Vercel Edge | ✅ | And other edge runtimes. |

<div class="callout callout-info"><span class="ic">ℹ️</span><p>ChaCha20-Poly1305 and scrypt use Node's native <code>crypto</code> module and are Node-only. Everything else runs on the universal Web Crypto API.</p></div>
