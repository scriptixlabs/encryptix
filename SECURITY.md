# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

Only the latest major version receives security patches. If you are on an older version, please upgrade.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

### Preferred: GitHub Security Advisories

Report vulnerabilities privately via:
[https://github.com/scriptixlabs/encryptix/security/advisories/new](https://github.com/scriptixlabs/encryptix/security/advisories/new)

This is the fastest path — you'll get a response within **48 hours**.

### Alternative: Email

Send a PGP-encrypted email to: **security@scriptixlabs.com**

Include in your report:
- A description of the vulnerability and its impact
- Steps to reproduce, or a minimal proof-of-concept
- Affected versions
- Any suggested mitigations (optional)

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Fix + patch release | 14 days for critical, 30 days for high |
| Public disclosure | Coordinated with reporter |

We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/Wiki/Coordinated+Vulnerability+Disclosure+Guidance). You will be credited in the release notes unless you prefer to remain anonymous.

---

## Scope

**In scope:**
- Cryptographic implementation errors (incorrect algorithm implementations, weak defaults)
- Authentication or integrity bypass vulnerabilities
- Key material leakage or exposure
- Timing side-channel vulnerabilities
- Padding oracle or other chosen-ciphertext attacks
- Vulnerabilities in the TOTP/HOTP implementation
- Incorrect handling of error cases that could leak information

**Out of scope:**
- Vulnerabilities in your application code that uses this library
- "Vulnerabilities" that require physical access to the machine
- Social engineering
- Issues in development dependencies (report to them directly)

---

## Security Design Notes

This library is built on the following security principles:

- **AEAD only** — all symmetric ciphers provide authenticated encryption. There is no unauthenticated mode.
- **HKDF key derivation** — master keys are never used directly. Each purpose derives an independent sub-key.
- **Purpose binding** — all payloads bind to a purpose string in the AAD. Cross-purpose decryption is cryptographically impossible.
- **Non-extractable keys** — Web Crypto `CryptoKey` objects are marked non-extractable where possible.
- **Constant-time comparisons** — HMAC verification and token comparison use timing-safe routines.
- **Rejection sampling** — all random generation uses unbiased sampling.
- **Versioned payloads** — the binary format is self-describing and forward-compatible.

We follow the [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) and relevant NIST guidelines.
