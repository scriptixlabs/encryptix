---
title: Batch Operations
description: Encrypt or decrypt many values at once, with uniform, mixed, or fault-tolerant variants.
---

# Batch Operations

Bulk helpers for encrypting/decrypting many values efficiently. Available both as `EncryptixClient` methods and as standalone exports.

## Uniform batches

Same purpose and options for every item.

```ts
const payloads = await enc.encryptBatch(['a', 'b', 'c'], 'user:field');
const plains   = await enc.decryptBatch(payloads, 'user:field');
```

```ts
encryptBatch(items: string[], purpose: string, options?: EncryptOptions): Promise<string[]>
decryptBatch(payloads: string[], purpose: string, options?: DecryptOptions): Promise<string[]>
```

## Mixed batches

Each item carries its own purpose and options.

```ts
const payloads = await enc.encryptBatchMixed([
  { plaintext: 'card', purpose: 'payment:card', options: { ttlSeconds: 600 } },
  { plaintext: 'email', purpose: 'user:email' },
]);

const plains = await enc.decryptBatchMixed([
  { payload: payloads[0], purpose: 'payment:card' },
  { payload: payloads[1], purpose: 'user:email' },
]);
```

## Fault-tolerant batches

`*Safe` variants never reject — each result reports success or the error, so one bad item doesn't fail the whole batch.

```ts
const results = await enc.decryptBatchSafe(payloads, 'user:field');
for (const r of results) {
  if (r.ok) console.log(r.value);
  else console.warn(r.error.code);
}
```

```ts
encryptBatchSafe(items: string[], purpose: string, options?: EncryptOptions): Promise<BatchResult<string>[]>
decryptBatchSafe(payloads: string[], purpose: string, options?: DecryptOptions): Promise<BatchResult<string>[]>
```
