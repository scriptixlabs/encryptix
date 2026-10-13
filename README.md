# @scriptixlabs/encryptix

> A secure, zero-dependency encryption library for Node.js, browsers, and edge runtimes.

[![npm version](https://img.shields.io/npm/v/@scriptixlabs/encryptix.svg)](https://www.npmjs.com/package/@scriptixlabs/encryptix)
[![license](https://img.shields.io/npm/l/@scriptixlabs/encryptix.svg)](./LICENSE)
[![types](https://img.shields.io/badge/types-TypeScript-blue.svg)](./src/types/index.ts)

📖 **[Documentation](https://scriptixlabs.github.io/encryptix/)** · [API Reference](https://scriptixlabs.github.io/encryptix/api/overview)

---

## Why encryptix?

| Feature | encryptix |
|---|---|
| Zero runtime dependencies | ✅ |
| Node.js 18+, browsers, edge runtimes (Cloudflare Workers, Deno, Vercel Edge) | ✅ |
| AES-256-GCM + ChaCha20-Poly1305 + RSA-OAEP | ✅ |
| AES-SIV deterministic encryption (searchable fields) | ✅ |
| Envelope encryption (DEK/KEK pattern) | ✅ |
| Password-based key derivation (scrypt / PBKDF2) | ✅ |
| Signed tokens (lightweight JWT alternative) | ✅ |
| Streaming encryption (files, large data) | ✅ |
| Object encryption with transparent TTL | ✅ |
| HKDF key derivation with purpose scoping | ✅ |
| Key rotation with backward-compatible payloads | ✅ |
| Key fingerprinting for multi-key debugging | ✅ |
| Full TypeScript types | ✅ |

---

## Installation

```bash
npm install @scriptixlabs/encryptix
pnpm add @scriptixlabs/encryptix
yarn add @scriptixlabs/encryptix
```

---

## Quick Start

```ts
import { EncryptixClient, generateMasterKey } from '@scriptixlabs/encryptix';

// One-time: generate and store your master key
const key = generateMasterKey(); // 64-char hex = 32 bytes
// → store as ENCRYPTIX_KEY in your environment

// Create a client (reads ENCRYPTIX_KEY from env automatically)
const enc = new EncryptixClient();

// Encrypt and decrypt
const payload = await enc.encrypt('user@example.com', 'user:email');
const email   = await enc.decrypt(payload, 'user:email');
```

---

## Core Concepts

### Purpose scoping

Every operation takes a `purpose` string. It's included in the payload's AAD (Additional Authenticated Data) and in the HKDF key derivation info. **Decrypting with the wrong purpose always fails — even with the correct key.**

```ts
await enc.encrypt(cardNumber, 'payment:card');
await enc.encrypt(sessionToken, 'auth:session');
await enc.encrypt(userEmail, 'user:pii:email');
// Each of these uses a completely separate derived key
```

### Zero dependencies

Everything uses the Web Crypto API (`globalThis.crypto.subtle`), available natively in Node 18+, all modern browsers, and edge runtimes. The only exception is ChaCha20-Poly1305 and scrypt, which use Node's native `crypto` module.

---

## Features

### Symmetric Encryption

```ts
// AES-256-GCM (default — works everywhere)
const payload = await enc.encrypt('secret', 'my:purpose');
const plain   = await enc.decrypt(payload, 'my:purpose');

// ChaCha20-Poly1305 (Node.js only)
const enc2 = new EncryptixClient({ algorithm: 'chacha20-poly1305' });
const payload2 = await enc2.encrypt('secret', 'my:purpose');

// Extra AAD — bind ciphertext to a specific user, request, etc.
const payload3 = await enc.encrypt('data', 'auth:token', { aad: userId });
await enc.decrypt(payload3, 'auth:token', { aad: userId });

// TTL — payload auto-expires after N seconds (expiry embedded in AAD, can't be stripped)
const payload4 = await enc.encrypt('data', 'auth:token', { ttlSeconds: 3600 });
```

---

### Object Encryption with TTL

Encrypts any JSON-serializable value. Expiry is embedded inside the ciphertext and verified transparently on decrypt — no extra parameters needed.

```ts
const payload = await enc.encryptObject(
  { userId: '123', role: 'admin' },
  'user:session',
  { ttlSeconds: 3600 }
);

// Decrypts AND checks expiry automatically
const session = await enc.decryptObject<{ userId: string; role: string }>(payload, 'user:session');

// Throws EncryptixError { code: 'PAYLOAD_EXPIRED' } if expired
```

---

### Deterministic Encryption (AES-SIV)

Same input → same ciphertext. Use for encrypted database indexes, searchable fields, or deduplication.

```ts
// Store encrypted email in DB with a searchable index
const encEmail = await enc.encryptDeterministic(userEmail, 'user:email');
// SELECT * WHERE encrypted_email = ?  — works without decrypting every row

// Bind to context for extra safety
const enc1 = await enc.encryptDeterministic(value, 'field:x', { aad: tenantId });
const enc2 = await enc.encryptDeterministic(value, 'field:x', { aad: tenantId });
// enc1 === enc2 ✓ — same tenant, same value

const enc3 = await enc.encryptDeterministic(value, 'field:x', { aad: otherTenantId });
// enc1 !== enc3 ✓ — different tenant context

const plain = await enc.decryptDeterministic(encEmail, 'user:email');
```

> ⚠️ Only use when equality-leakage is acceptable. For fields where patterns must be hidden, use `encrypt()`.

---

### Envelope Encryption (DEK/KEK)

Generates a fresh random Data Encryption Key (DEK) per payload, wrapped with a Key Encryption Key (KEK) derived from your master key.

```ts
// Encrypt
const envelope = await enc.envelopeEncrypt(sensitiveData, 'record:patient-data');
// Store envelope as JSON — it contains wrappedDek + ciphertext

// Decrypt
const data = await enc.envelopeDecrypt(envelope, 'record:patient-data');

// Rotating the KEK: re-wrap the DEK without re-encrypting data
// (fetch wrappedDek, unwrap with old KEK, re-wrap with new KEK)

// envelope.kekFingerprint tells you which KEK version encrypted this envelope
console.log(envelope.kekFingerprint); // → 'a3f9e2b1...' (16-char hex)
```

The envelope structure:
```ts
{
  wrappedDek: string;      // DEK encrypted with KEK via AES-KW
  ciphertext: string;      // data encrypted with DEK
  wrapAlgorithm: 'AES-KW';
  dataAlgorithm: 'aes-256-gcm';
  kekFingerprint: string;  // which KEK encrypted this
  version: 1;
}
```

---

### Signed Tokens (Lightweight JWT Alternative)

HMAC-SHA256 signed, purpose-bound, optionally expiring tokens. No algorithm confusion attacks (alg is fixed, not user-controlled).

```ts
// Sign a structured payload
const token = await enc.sign(
  { userId: '123', role: 'admin' },
  'auth:access',
  { ttlSeconds: 3600 }
);
// → 'eyJhbGci....eyJ1c2VyS....ABC123...' (base64url, dot-separated)

// Verify — never throws on invalid tokens (unless throwOnExpiry is set)
const result = await enc.verify<{ userId: string; role: string }>(token, 'auth:access');

if (result.valid) {
  console.log(result.payload);      // { userId: '123', role: 'admin' }
  console.log(result.remainingTtl); // seconds until expiry
} else {
  console.log(result.reason); // 'expired' | 'invalid_signature' | 'malformed'
}

// Throw on expiry
await enc.verify(token, 'auth:access', { throwOnExpiry: true });
// → throws EncryptixError { code: 'TOKEN_EXPIRED' }
```

---

### Streaming Encryption

Encrypts large data (files, network streams) chunk-by-chunk. Each chunk has its own auth tag — truncation and reordering attacks are cryptographically prevented.

```ts
// Encrypt a file
const encTransform = enc.encryptStream({ purpose: 'file:upload' });
await fs.createReadStream('file.pdf')
  .pipeThrough(encTransform)
  .pipeTo(uploadWritable);

// Decrypt
const decTransform = enc.decryptStream({ purpose: 'file:upload' });
await downloadReadable
  .pipeThrough(decTransform)
  .pipeTo(fs.createWriteStream('file.pdf'));

// Works with any chunk size — defaults to 64 KiB per chunk
const encTransform2 = enc.encryptStream({
  purpose: 'file:large',
  chunkSize: 256 * 1024, // 256 KiB chunks
});
```

---

### Password-Based Key Derivation

Derives a strong encryption key from a human password. Uses scrypt in Node.js (memory-hard, GPU-resistant) or PBKDF2 in browsers/edge.

```ts
import { deriveKeyFromPassword } from '@scriptixlabs/encryptix';

// Derive key from password (generates a random salt)
const { keyHex, saltHex, algorithm, params } = await deriveKeyFromPassword(
  'my-secure-passphrase',
  'user:vault',
  { algorithm: 'scrypt' } // default in Node; use 'pbkdf2' for browser
);

// IMPORTANT: Store saltHex in your DB alongside the encrypted data
// Without the same salt, you cannot re-derive the same key

// Encrypt user's data with their password-derived key
const userEnc = new EncryptixClient({ key: keyHex });
const encrypted = await userEnc.encrypt(sensitiveData, 'user:vault');

// Later: re-derive key from stored salt to decrypt
const { keyHex: derivedKey } = await deriveKeyFromPassword(
  userPassword,
  'user:vault',
  { algorithm, ...params, saltHex }
);
const decEnc = new EncryptixClient({ key: derivedKey });
const decrypted = await decEnc.decrypt(encrypted, 'user:vault');
```

---

### Key Rotation

```ts
const v1 = new EncryptixClient({ key: process.env.ENCRYPTIX_KEY });
const oldPayload = await v1.encrypt('old-secret', 'user:token');

// Rotate to a new key
const newKey = generateMasterKey(); // Store as new ENCRYPTIX_KEY
const v2 = v1.rotate(newKey);

// v2 encrypts with newKey, decrypts both old and new payloads
await v2.decrypt(oldPayload, 'user:token'); // ✅ uses v1 key automatically
await v2.decrypt(await v2.encrypt('new', 'user:token'), 'user:token'); // ✅
```

---

### Key Fingerprinting

```ts
const fp = await enc.keyFingerprint();
// → { fingerprint: 'a3f9e2b1c4d5e6f7', version: 1 }

// Useful for debugging: log which key encrypted a payload
// Fingerprint is SHA-256(key)[0:8] — non-reversible, safe to log
```

---

### RSA-OAEP

```ts
import { generateRSAKeyPair } from '@scriptixlabs/encryptix';

const { publicKey, privateKey } = await generateRSAKeyPair(2048);

const ciphertext = await enc.encryptRSA('short-secret', publicKey);
const plaintext  = await enc.decryptRSA(ciphertext, privateKey);
```

---

### Hashing, HMAC & Tokens

```ts
// SHA-256/384/512 hash
const digest = await enc.hash('my-token', 'sha256', 'hex');

// HMAC with no key → signs with the client's raw master key (intentional default)
const sig   = await enc.hmac(webhookBody);
const valid = await enc.verifyHmac(webhookBody, sig); // constant-time

// Third-party webhook secrets are plain text: say so with keyEncoding: 'utf8'.
// String keys are hex-decoded by default; a non-hex string throws INVALID_KEY.
// Shopify sends base64(HMAC-SHA256(rawBody, secret)) in X-Shopify-Hmac-Sha256:
const ok = await enc.verifyHmac(rawBody, req.headers['x-shopify-hmac-sha256'], process.env.SHOPIFY_SECRET!, {
  keyEncoding: 'utf8',   // 'hex' (default) | 'utf8' | 'base64' | 'base64url'
  encoding: 'base64',    // signature/output encoding: 'hex' (default) | 'base64' | 'base64url'
});

// Random token (hex by default)
const token = enc.generateToken(32, 'hex');       // 64-char hex
const apiKey = enc.generateApiKey('sk');          // 'sk_4xG9cN7m...'
const uuid   = enc.generateUUID();                // UUID v4
```

---

## Configuration

```ts
const enc = new EncryptixClient({
  key: 'your-64-char-hex-key',       // or set ENCRYPTIX_KEY env var
  algorithm: 'aes-256-gcm',          // 'aes-256-gcm' | 'chacha20-poly1305'
  encoding: 'base64',                // 'base64' | 'base64url' | 'hex'
  hashAlgorithm: 'sha256',           // 'sha256' | 'sha384' | 'sha512'
  namespace: 'myapp',                // HKDF info prefix (default: 'encryptix')
  keychain: { 1: 'old-key-hex' },   // for key rotation
});
```

---

## Error Handling

All errors are `EncryptixError` with a machine-readable `code`:

```ts
import { EncryptixError } from '@scriptixlabs/encryptix';

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

---

## Payload Binary Layout

```
Symmetric payload:
  [1B version][1B algo_id][2B key_version][12B iv][16B tag][N bytes ciphertext]

Deterministic (AES-SIV):
  [1B version][1B algo_id=0x03][16B SIV][N bytes ciphertext]

Streaming chunks:
  Header: [4B magic "ENCX"][1B version][1B algo][12B stream_nonce][4B chunk_size]
  Chunk:  [4B index][12B iv][16B tag][N bytes ciphertext]
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `ENCRYPTIX_KEY` | 64-char hex master key (required unless `key` is passed to constructor) |

---

## API Reference

| Method | Description |
|---|---|
| `encrypt(plaintext, purpose, opts?)` | AES-GCM or ChaCha20 encrypt |
| `decrypt(payload, purpose, opts?)` | Symmetric decrypt |
| `encryptObject(value, purpose, opts?)` | Encrypt any JSON value with optional TTL |
| `decryptObject(payload, purpose, opts?)` | Decrypt and verify TTL automatically |
| `encryptDeterministic(plaintext, purpose, opts?)` | AES-SIV deterministic encrypt |
| `decryptDeterministic(payload, purpose, opts?)` | AES-SIV decrypt + verify |
| `envelopeEncrypt(plaintext, purpose, opts?)` | DEK/KEK envelope encrypt |
| `envelopeDecrypt(envelope, purpose, opts?)` | Unwrap DEK, decrypt data |
| `sign(payload, purpose, opts?)` | HMAC-SHA256 signed token |
| `verify(token, purpose, opts?)` | Verify signed token → VerifyTokenResult |
| `encryptStream(opts)` | → TransformStream (encrypt chunks) |
| `decryptStream(opts)` | → TransformStream (decrypt chunks) |
| `encryptRSA(plaintext, publicKeyPEM)` | RSA-OAEP encrypt |
| `decryptRSA(ciphertext, privateKeyPEM)` | RSA-OAEP decrypt |
| `generateRSAKeyPair(bits?)` | Generate 2048/4096 RSA key pair (PEM) |
| `deriveKeyFromPassword(pass, purpose, opts?)` | scrypt/PBKDF2 password → keyHex |
| `hash(input, alg?, enc?)` | SHA-256/384/512 |
| `hmac(msg, key?, alg?\|opts?)` | HMAC sign (key: hex string, `Uint8Array`, or any string with `keyEncoding`) |
| `verifyHmac(msg, sig, key?, alg?\|opts?)` | Constant-time HMAC verify |
| `keyFingerprint()` | Short non-reversible key identifier |
| `rotate(newKeyHex)` | Key rotation → new EncryptixClient |
| `generateToken(bytes?, enc?)` | Cryptographic random token |
| `generateApiKey(prefix?, bytes?)` | Prefixed API key |
| `generateUUID()` | UUID v4 |

---

## Security Considerations

- **Store your key safely.** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Never commit it.
- **Purpose strings are security boundaries.** A token encrypted for `auth:session` cannot be used as `payment:card`.
- **All symmetric ciphers are AEAD.** Authentication is always on — there is no unauthenticated mode.
- **Keys are non-extractable** in browser/edge (Web Crypto). Raw key bytes never leave the crypto subsystem.
- **Timing-safe comparisons** are used in HMAC verification and AES-SIV authentication.
- **AES-SIV is deterministic by design.** Only use it where equality-leakage is acceptable.
- **Always store the `saltHex`** from `deriveKeyFromPassword`. Without it you cannot re-derive the same key.

---

## License

MIT © [Scriptix Labs](https://github.com/scriptixlabs)
