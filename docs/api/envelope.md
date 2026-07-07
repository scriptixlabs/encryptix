---
title: Envelope & Multi-Recipient
description: DEK/KEK envelope encryption and encrypting a payload for many recipients.
---

# Envelope Encryption (DEK/KEK)

Generates a fresh random Data Encryption Key (DEK) per payload, wrapped with a Key Encryption Key (KEK) derived from your master key. This lets you rotate the KEK without re-encrypting the data.

```ts
// Encrypt — store the returned envelope as JSON
const envelope = await enc.envelopeEncrypt(sensitiveData, 'record:patient-data');

// Decrypt
const data = await enc.envelopeDecrypt(envelope, 'record:patient-data');

// Which KEK version encrypted this envelope?
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

```ts
envelopeEncrypt(plaintext: string, purpose: string, options?: EnvelopeEncryptOptions): Promise<EnvelopePayload>
envelopeDecrypt(envelope: EnvelopePayload, purpose: string, options?: EnvelopeDecryptOptions): Promise<string>
```

---

# Multi-Recipient Encryption

Encrypt one payload so that **any** of several recipients can decrypt it with their own private key — the DEK is wrapped once per recipient public key.

```ts
const envelope = await enc.multiRecipientEncrypt(secret, [
  { id: 'alice', publicKeyPEM: alicePub },
  { id: 'bob',   publicKeyPEM: bobPub },
]);

const plain = await multiRecipientDecrypt(envelope, 'alice', alicePrivPEM);

// Add or remove recipients without re-encrypting the payload
const updated  = await enc.addRecipient(envelope, 'alice', alicePrivPEM, { id: 'carol', publicKeyPEM: carolPub });
const narrowed = enc.removeRecipient(envelope, 'bob');
```

```ts
multiRecipientEncrypt(plaintext: string, recipients: RecipientKey[], options?: MultiRecipientOptions): Promise<MultiRecipientEnvelope>
multiRecipientDecrypt(envelope: MultiRecipientEnvelope, recipientId: string, privateKeyPEM: string): Promise<string>
addRecipient(envelope, existingId, existingPrivateKeyPEM, newRecipient): Promise<MultiRecipientEnvelope>
removeRecipient(envelope, recipientId): MultiRecipientEnvelope
```
