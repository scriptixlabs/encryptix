# Changelog

All notable changes to `@ppabari/encryptix` are documented here.

This project follows [Conventional Commits](https://www.conventionalcommits.org/) and [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2025-06-01

### 🎉 Initial Release

#### Algorithms
- **feat**: AES-256-GCM authenticated encryption (universal — Node.js, browsers, edge)
- **feat**: ChaCha20-Poly1305 authenticated encryption (Node.js)
- **feat**: RSA-OAEP asymmetric encryption / decryption
- **feat**: RSA-PSS digital signatures (sign + verify)
- **feat**: ECDH key agreement (P-256, P-384, P-521)
- **feat**: ECDSA digital signatures (P-256, P-384, P-521)
- **feat**: AES-SIV deterministic authenticated encryption (searchable fields)
- **feat**: Streaming encryption via Web Streams API (chunked AEAD)
- **feat**: Envelope encryption (DEK/KEK pattern with AES-KW)
- **feat**: Multi-recipient envelope encryption (one ciphertext, N RSA recipients)
- **feat**: TOTP (RFC 6238) and HOTP (RFC 4226) one-time passwords
- **feat**: Signed tokens (HMAC-SHA256, lightweight JWT alternative)

#### Key Management
- **feat**: HKDF key derivation scoped by purpose string
- **feat**: Key rotation with backward-compatible versioned payloads
- **feat**: Key fingerprinting (short non-reversible identifier)
- **feat**: Key metadata store (createdAt, purpose, algorithm per version)
- **feat**: Key import/export in hex, base64, base64url, JWK formats
- **feat**: Password-based key derivation (scrypt on Node.js, PBKDF2 universal)

#### Developer Utilities
- **feat**: `encryptObject` / `decryptObject` with transparent TTL
- **feat**: `encryptBatch` / `decryptBatch` parallel operations
- **feat**: `encryptBatchMixed` for heterogeneous fields
- **feat**: `encryptBatchSafe` / `decryptBatchSafe` for partial-failure handling
- **feat**: `encryptDeterministic` / `decryptDeterministic` (AES-SIV)
- **feat**: `reEncrypt` — purpose/key migration without raw plaintext exposure
- **feat**: `inspectPayload` — read metadata without decrypting
- **feat**: `inspectToken` — decode token header/payload without verifying
- **feat**: `inspectStreamHeader` — read stream metadata

#### Encoding & Codec
- **feat**: Base32 encode/decode (RFC 4648)
- **feat**: Hex encode/decode with validation
- **feat**: Base64 / base64url encode/decode
- **feat**: `convertEncoding` — convert between formats in one call
- **feat**: `safeCompare` — constant-time string/buffer comparison

#### Secure Random
- **feat**: `secureRandomInt(min, max)` — unbiased rejection sampling
- **feat**: `secureRandomString(len, charset)` — per-character rejection sampling
- **feat**: `secureRandomChoice(array)` — uniform random selection
- **feat**: `secureRandomSample(array, n)` — sampling without replacement
- **feat**: `secureRandomShuffle(array)` — Fisher-Yates with crypto randomness
- **feat**: `secureRandomFloat()` — uniform [0, 1)
- **feat**: `secureRandomBytes(n)` — raw random bytes
- **feat**: `securePassphrase(wordList, n)` — diceware-style passphrases
- **feat**: Named `CHARSETS` — alphanumeric, readable, printable, numeric, urlSafe

#### Security Infrastructure
- **feat**: `EncryptixError` with machine-readable `code` on every throw
- **feat**: `EncryptixError.from(err, code, message)` — wrap external errors
- **feat**: `EncryptixError.is(err, code)` — type-safe error guard
- **feat**: `EncryptixError.toJSON()` — serializable for structured logging
- **feat**: `zeroize(buffer)` — wipe sensitive bytes from memory
- **feat**: `zeroizeAll(...buffers)` — bulk wipe
- **feat**: `withZeroize(buffer, fn)` — guaranteed wipe even on throw

#### Other
- **feat**: `generateMasterKey()` — cryptographically random 256-bit key
- **feat**: `generateToken()`, `generateApiKey()`, `generateUUID()` — token generation
- **feat**: `hash()` — SHA-256/384/512
- **feat**: `hmac()` + `verifyHmac()` — HMAC-SHA signing and constant-time verify
- **feat**: `totpKeyUri()` — otpauth:// URI for QR code generation
- **feat**: `toBase32()` / `fromBase32()` — standalone base32 conversion
- **feat**: `createKeyMetadataStore()` — key version registry

---

## Versioning Guide

| Commit prefix | Version bump |
|---------------|--------------|
| `feat:`        | Minor (1.x.0) |
| `fix:`         | Patch (1.0.x) |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) |
| `docs:`, `chore:`, `refactor:` | No version bump |

---

## Security Advisories

See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy.
Past advisories will be listed here after coordinated disclosure.
