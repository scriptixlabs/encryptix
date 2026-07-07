---
title: Security
description: Security model, guarantees, and operational guidance.
---

# Security Considerations

- **Store your key safely.** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Never commit it.
- **Purpose strings are security boundaries.** A token encrypted for `auth:session` cannot be used as `payment:card` — the purpose is bound into both the derived key and the AAD.
- **All symmetric ciphers are AEAD.** Authentication is always on — there is no unauthenticated mode.
- **Keys are non-extractable** in browser/edge (Web Crypto). Raw key bytes never leave the crypto subsystem.
- **Timing-safe comparisons** are used in HMAC verification and AES-SIV authentication.
- **AES-SIV is deterministic by design.** Only use it where equality-leakage is acceptable — see [Deterministic Encryption]({{ '/api/deterministic/' | relative_url }}).
- **Always store the `saltHex`** from [`deriveKeyFromPassword`]({{ '/api/password-kdf/' | relative_url }}). Without it you cannot re-derive the same key.

## Reporting a vulnerability

Please report security issues privately per the project's [`SECURITY.md`]({{ site.github_url }}/blob/main/SECURITY.md) rather than opening a public issue.

## Guarantees at a glance

| Property | Guarantee |
|---|---|
| Confidentiality | AES-256-GCM / ChaCha20-Poly1305 / AES-SIV |
| Integrity &amp; authenticity | AEAD tag verified on every decrypt |
| Key separation | Per-purpose HKDF derivation from the master key |
| Context binding | Optional `aad` binds ciphertext to a user/request/tenant |
| Expiry | TTL embedded in AAD — cannot be stripped without detection |
| Forward compatibility | Versioned payloads; key rotation via keychain |
