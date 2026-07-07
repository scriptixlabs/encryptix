---
title: API Overview
description: The full encryptix method and export reference, grouped by capability.
---

# API Overview

Everything is exported from the single entry point `{{ site.npm_package }}`. Most functionality lives on the `EncryptixClient`; a set of standalone helpers is exported for key generation, encoding, OTP, and randomness.

```ts
import { EncryptixClient, generateMasterKey } from '{{ site.npm_package }}';
const enc = new EncryptixClient();
```

## Client methods

| Method | Description |
|---|---|
| `encrypt(plaintext, purpose, opts?)` | AES-GCM or ChaCha20 encrypt → [Symmetric]({{ '/api/symmetric/' | relative_url }}) |
| `decrypt(payload, purpose, opts?)` | Symmetric decrypt |
| `encryptObject(value, purpose, opts?)` | Encrypt any JSON value with optional TTL |
| `decryptObject(payload, purpose, opts?)` | Decrypt and verify TTL automatically |
| `encryptDeterministic(plaintext, purpose, opts?)` | AES-SIV deterministic encrypt → [Deterministic]({{ '/api/deterministic/' | relative_url }}) |
| `decryptDeterministic(payload, purpose, opts?)` | AES-SIV decrypt + verify |
| `envelopeEncrypt(plaintext, purpose, opts?)` | DEK/KEK envelope encrypt → [Envelope]({{ '/api/envelope/' | relative_url }}) |
| `envelopeDecrypt(envelope, purpose, opts?)` | Unwrap DEK, decrypt data |
| `multiRecipientEncrypt(plaintext, recipients, opts?)` | Encrypt for many public keys |
| `addRecipient(...)` / `removeRecipient(...)` | Manage recipients of an envelope |
| `sign(payload, purpose, opts?)` | HMAC-SHA256 signed token → [Signed Tokens]({{ '/api/signed-tokens/' | relative_url }}) |
| `verify(token, purpose, opts?)` | Verify signed token → `VerifyTokenResult` |
| `encryptStream(opts)` / `decryptStream(opts)` | `TransformStream` chunk encryption → [Streaming]({{ '/api/streaming/' | relative_url }}) |
| `encryptBatch` / `decryptBatch` / `*Mixed` / `*Safe` | Bulk operations → [Batch]({{ '/api/batch/' | relative_url }}) |
| `encryptRSA` / `decryptRSA` / `generateRSAKeyPair` | RSA-OAEP → [Asymmetric]({{ '/api/asymmetric/' | relative_url }}) |
| `signRSA` / `verifyRSA` / `generateRSAPSSKeyPair` | RSA-PSS signatures |
| `generateECDHKeyPair` / `generateECDSAKeyPair` / `signECDSA` / `verifyECDSA` | Elliptic-curve keys &amp; signatures |
| `deriveKeyFromPassword(pass, purpose, opts?)` | scrypt/PBKDF2 password → keyHex → [Password KDF]({{ '/api/password-kdf/' | relative_url }}) |
| `generateTOTP` / `verifyTOTP` / `generateHOTP` / `totpKeyUri` | OTP → [OTP]({{ '/api/otp/' | relative_url }}) |
| `hash` / `hmac` / `verifyHmac` | Hashing &amp; HMAC → [Utilities]({{ '/api/utilities/' | relative_url }}) |
| `generateToken` / `generateApiKey` / `generateUUID` | Random tokens &amp; IDs |
| `keyFingerprint()` | Short non-reversible key identifier → [Key Management]({{ '/api/key-management/' | relative_url }}) |
| `rotate(newKeyHex)` | Key rotation → new `EncryptixClient` |
| `inspectPayload(payload)` | Decode a payload header without the key |

## Standalone exports

| Group | Exports |
|---|---|
| **Keys** | `generateMasterKey`, `generateRSAKeyPair`, `generateRSAPSSKeyPair`, `generateECDHKeyPair`, `generateECDSAKeyPair` |
| **Asymmetric** | `rsaEncrypt`, `rsaDecrypt`, `rsaPssSign`, `rsaPssVerify`, `deriveSharedSecret`, `ecdsaSign`, `ecdsaVerify` |
| **OTP** | `generateTOTPSecret`, `generateTOTP`, `verifyTOTP`, `generateHOTP`, `totpKeyUri`, `toBase32`, `fromBase32` |
| **Multi-recipient** | `multiRecipientEncrypt`, `multiRecipientDecrypt`, `addRecipient`, `removeRecipient` |
| **Tokens & hashing** | `hash`, `hmac`, `verifyHmac`, `generateToken`, `generateApiKey`, `generateUUID` |
| **Secure random** | `secureRandomBytes`, `secureRandomInt`, `secureRandomFloat`, `secureRandomString`, `secureRandomChoice`, `secureRandomSample`, `secureRandomShuffle`, `securePassphrase`, `CHARSETS` |
| **Batch** | `encryptBatch`, `decryptBatch`, `encryptBatchMixed`, `decryptBatchMixed`, `encryptBatchSafe`, `decryptBatchSafe` |
| **Encoding** | `base32Encode/Decode`, `hexEncode/Decode`, `base64Encode/Decode`, `base64urlEncode`, `convertEncoding`, `safeCompare` |
| **Inspection** | `inspectPayload`, `inspectStreamHeader`, `inspectToken` |
| **Key management** | `zeroize`, `zeroizeAll`, `withZeroize`, `createKeyMetadataStore`, `reEncrypt`, `reEncryptBatch`, `exportKeyToJWK`, `importKeyFromJWK`, `serializeKey`, `deserializeKey` |
| **KDF** | `deriveKeyFromPassword` |
| **Errors** | `EncryptixError` |

<div class="callout callout-tip"><span class="ic">🧭</span><p>New here? Start with the <a href="{{ '/guide/getting-started/' | relative_url }}">Getting Started</a> guide and <a href="{{ '/guide/core-concepts/' | relative_url }}">Core Concepts</a> (purpose scoping), then dive into the capability pages in the sidebar.</p></div>
