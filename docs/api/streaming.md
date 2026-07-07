---
title: Streaming Encryption
description: Chunk-by-chunk AEAD for files and large data via Web Streams.
---

# Streaming Encryption

Encrypts large data (files, network streams) chunk-by-chunk. Each chunk has its own auth tag — **truncation and reordering attacks are cryptographically prevented**. Returns a standard `TransformStream`.

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
```

## Chunk size

Defaults to 64 KiB per chunk; tune it for your workload.

```ts
const encTransform = enc.encryptStream({
  purpose: 'file:large',
  chunkSize: 256 * 1024, // 256 KiB chunks
});
```

```ts
encryptStream(options: StreamEncryptOptions): TransformStream<Uint8Array, Uint8Array>
decryptStream(options: StreamDecryptOptions): TransformStream<Uint8Array, Uint8Array>
```

The stream format embeds a magic header (`ENCX`), version, algorithm, a stream nonce, and per-chunk index/iv/tag — see the [payload layout]({{ '/guide/core-concepts/' | relative_url }}). A missing or reordered chunk surfaces as a `STREAM_ERROR`.
