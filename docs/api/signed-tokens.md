---
title: Signed Tokens
description: HMAC-SHA256 signed, purpose-bound, optionally expiring tokens — a JWT alternative.
---

# Signed Tokens

A lightweight JWT alternative: HMAC-SHA256 signed, purpose-bound, optionally expiring tokens. **No algorithm-confusion attacks** — the algorithm is fixed, not user-controlled.

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
  console.log(result.reason);       // 'expired' | 'invalid_signature' | 'malformed'
}
```

## Throw on expiry

```ts
await enc.verify(token, 'auth:access', { throwOnExpiry: true });
// → throws EncryptixError { code: 'TOKEN_EXPIRED' }
```

```ts
sign<T>(payload: T, purpose: string, options?: SignTokenOptions): Promise<string>
verify<T>(token: string, purpose: string, options?: VerifyTokenOptions): Promise<VerifyTokenResult<T>>
```

`VerifyTokenResult<T>`:

```ts
type VerifyTokenResult<T> =
  | { valid: true;  payload: T; remainingTtl?: number }
  | { valid: false; reason: 'expired' | 'invalid_signature' | 'malformed' };
```

<div class="callout callout-tip"><span class="ic">🎫</span><p>Tokens are bound to their <code>purpose</code>. A token signed for <code>auth:access</code> will not verify under <code>auth:refresh</code> — no separate audience field required.</p></div>
