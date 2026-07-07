---
title: Asymmetric (RSA / EC)
description: RSA-OAEP encryption, RSA-PSS & ECDSA signatures, and ECDH key agreement.
---

# Asymmetric Cryptography

RSA and elliptic-curve primitives, exposed both as `EncryptixClient` methods and standalone functions. Keys are PEM strings.

## RSA-OAEP (encryption)

```ts
import { generateRSAKeyPair } from '{{ site.npm_package }}';

const { publicKey, privateKey } = await generateRSAKeyPair(2048);

const ciphertext = await enc.encryptRSA('short-secret', publicKey);
const plaintext  = await enc.decryptRSA(ciphertext, privateKey);
```

```ts
generateRSAKeyPair(modulusLength?: 2048 | 4096): Promise<RSAKeyPair>
encryptRSA(plaintext: string, publicKeyPEM: string, encoding?: Encoding): Promise<string>
decryptRSA(ciphertext: string, privateKeyPEM: string, encoding?: Encoding): Promise<string>
```

<div class="callout callout-info"><span class="ic">ℹ️</span><p>RSA-OAEP encrypts <em>short</em> payloads (e.g. a key). To protect large data, use it to wrap a symmetric key — see <a href="{{ '/api/envelope/' | relative_url }}">Envelope &amp; Multi-Recipient</a>.</p></div>

## RSA-PSS (signatures)

```ts
const { publicKey, privateKey } = await enc.generateRSAPSSKeyPair(2048);

const signature = await enc.signRSA(data, privateKey);
const valid     = await enc.verifyRSA(data, signature, publicKey); // → boolean
```

```ts
generateRSAPSSKeyPair(modulusLength?: 2048 | 4096): Promise<RSAKeyPair>
signRSA(data: string | Uint8Array, privateKeyPEM: string, encoding?: Encoding): Promise<string>
verifyRSA(data: string | Uint8Array, signature: string, publicKeyPEM: string, encoding?: Encoding): Promise<boolean>
```

## ECDSA (signatures)

Curves: `P-256` (default), `P-384`, `P-521`.

```ts
const { publicKey, privateKey } = await enc.generateECDSAKeyPair('P-256');

const signature = await enc.signECDSA(data, privateKey);
const valid     = await enc.verifyECDSA(data, signature, publicKey); // → boolean
```

```ts
generateECDSAKeyPair(curve?: ECCurve): Promise<ECKeyPair>
signECDSA(data: string | Uint8Array, privateKeyPEM: string, curve?: ECCurve, encoding?: Encoding): Promise<string>
verifyECDSA(data: string | Uint8Array, signature: string, publicKeyPEM: string, curve?: ECCurve, encoding?: Encoding): Promise<boolean>
```

## ECDH (key agreement)

Derive a shared secret between two parties from one side's private key and the other's public key.

```ts
const alice = await enc.generateECDHKeyPair('P-256');
const bob   = await enc.generateECDHKeyPair('P-256');

const aliceSecret = await enc.deriveSharedSecret(alice.privateKey, bob.publicKey);
const bobSecret   = await enc.deriveSharedSecret(bob.privateKey, alice.publicKey);
// aliceSecret === bobSecret ✓ — feed into HKDF / an EncryptixClient key
```

```ts
generateECDHKeyPair(curve?: ECCurve): Promise<ECKeyPair>
deriveSharedSecret(privateKeyPEM: string, peerPublicKeyPEM: string, curve?: ECCurve): Promise<string>
```

<div class="callout callout-tip"><span class="ic">🧩</span><p>The same functions are exported standalone — <code>rsaEncrypt</code>, <code>rsaDecrypt</code>, <code>rsaPssSign</code>, <code>rsaPssVerify</code>, <code>ecdsaSign</code>, <code>ecdsaVerify</code>, <code>deriveSharedSecret</code> — for use without a client instance.</p></div>
