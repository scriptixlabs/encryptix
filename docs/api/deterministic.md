---
title: Deterministic Encryption (AES-SIV)
description: Same input → same ciphertext, for searchable encrypted fields and dedup.
---

# Deterministic Encryption (AES-SIV)

Same input → same ciphertext. Use for encrypted database indexes, searchable fields, or deduplication.

```ts
// Store encrypted email in DB with a searchable index
const encEmail = await enc.encryptDeterministic(userEmail, 'user:email');
// SELECT * WHERE encrypted_email = ?  — works without decrypting every row

const plain = await enc.decryptDeterministic(encEmail, 'user:email');
```

## Context binding

Bind to a context (e.g. tenant) so equality only holds within that context.

```ts
const enc1 = await enc.encryptDeterministic(value, 'field:x', { aad: tenantId });
const enc2 = await enc.encryptDeterministic(value, 'field:x', { aad: tenantId });
// enc1 === enc2 ✓ — same tenant, same value

const enc3 = await enc.encryptDeterministic(value, 'field:x', { aad: otherTenantId });
// enc1 !== enc3 ✓ — different tenant context
```

```ts
encryptDeterministic(plaintext: string, purpose: string, options?: DeterministicEncryptOptions): Promise<string>
decryptDeterministic(payload: string, purpose: string, options?: DeterministicDecryptOptions): Promise<string>
```

<div class="callout callout-warning"><span class="ic">⚠️</span><p>Only use when equality-leakage is acceptable — identical plaintexts produce identical ciphertexts, which reveals matches. For fields where patterns must be hidden, use <a href="{{ '/api/symmetric/' | relative_url }}"><code>encrypt()</code></a> instead. AES-SIV is authenticated with a timing-safe tag check.</p></div>
