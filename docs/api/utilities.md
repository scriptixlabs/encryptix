---
title: Hashing, HMAC & Random
description: Hashing, HMAC, random tokens, secure randomness, encoding, and payload inspection.
---

# Hashing, HMAC &amp; Utilities

## Hashing

```ts
const digest = await enc.hash('my-token', 'sha256', 'hex');
```

```ts
hash(input: string | Uint8Array, algorithm?: 'sha256' | 'sha384' | 'sha512', encoding?: 'hex' | 'base64' | 'base64url'): Promise<string>
```

## HMAC

Signs with the master key by default; verification is constant-time.

```ts
const sig   = await enc.hmac(webhookBody);
const valid = await enc.verifyHmac(webhookBody, sig); // constant-time
```

```ts
hmac(message: string | Uint8Array, keyHex?: string, algorithm?: HashAlgorithm, encoding?: 'hex' | 'base64' | 'base64url'): Promise<string>
verifyHmac(message: string | Uint8Array, signature: string, keyHex?: string, algorithm?: HashAlgorithm, encoding?: 'hex' | 'base64' | 'base64url'): Promise<boolean>
```

## Random tokens &amp; IDs

```ts
const token  = enc.generateToken(32, 'hex'); // 64-char hex
const apiKey = enc.generateApiKey('sk');      // 'sk_4xG9cN7m...'
const uuid   = enc.generateUUID();            // UUID v4
```

## Secure randomness

Standalone, cryptographically secure random helpers (all bias-free).

```ts
import {
  secureRandomBytes, secureRandomInt, secureRandomString,
  secureRandomChoice, secureRandomSample, secureRandomShuffle,
  securePassphrase, CHARSETS,
} from '{{ site.npm_package }}';

secureRandomBytes(32);                       // Uint8Array(32)
secureRandomInt(1, 100);                     // unbiased integer in [1, 100]
secureRandomString(16, 'alphanumeric');      // or a CHARSETS key / custom charset
secureRandomChoice(['a', 'b', 'c']);         // one element
secureRandomSample(items, 3);                // 3 distinct elements
secureRandomShuffle(items);                  // Fisher–Yates shuffle
securePassphrase(wordList, 5, '-');          // 'stone-river-proud-flame-oak'
```

| Function | Returns |
|---|---|
| `secureRandomBytes(n)` | `Uint8Array` of `n` random bytes |
| `secureRandomInt(min, max)` | Unbiased integer in `[min, max]` |
| `secureRandomFloat()` | Float in `[0, 1)` |
| `secureRandomString(length, charset?)` | Random string |
| `secureRandomChoice(array)` | One random element |
| `secureRandomSample(array, n)` | `n` distinct random elements |
| `secureRandomShuffle(array)` | Shuffled copy |
| `securePassphrase(wordList, count?, sep?)` | Word-based passphrase |
| `CHARSETS` | Named charsets for `secureRandomString` |

## Encoding

```ts
import { base32Encode, hexEncode, base64urlEncode, convertEncoding, safeCompare } from '{{ site.npm_package }}';
```

`base32Encode/Decode`, `hexEncode/Decode`, `base64Encode/Decode`, `base64urlEncode`, and `convertEncoding(value, from, to)` convert between encodings. `safeCompare(a, b)` is a **constant-time** equality check for secrets.

## Payload inspection

Decode metadata from a payload/token **without the key** — handy for debugging and routing.

```ts
import { inspectPayload, inspectStreamHeader, inspectToken } from '{{ site.npm_package }}';

enc.inspectPayload(payload);   // → { version, algorithm, keyVersion, ... }
inspectStreamHeader(header);   // stream magic/version/algo/chunk size
inspectToken(token);           // signed-token header + claims (unverified)
```

<div class="callout callout-info"><span class="ic">ℹ️</span><p>Inspection never decrypts or verifies — it only parses public header fields. Never trust inspected claims for authorization; use <a href="{{ '/api/signed-tokens/' | relative_url }}"><code>verify()</code></a> instead.</p></div>
