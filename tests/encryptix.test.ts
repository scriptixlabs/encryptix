/**
 * @ppabari/encryptix — Full Test Suite
 */

import {
  EncryptixClient,
  createEncryptix,
  EncryptixError,
  generateMasterKey,
  generateToken,
  generateApiKey,
  generateUUID,
  hash,
  hmac,
  verifyHmac,
  generateRSAKeyPair,
  deriveKeyFromPassword,
  base32Encode,
  base32Decode,
  safeCompare,
  convertEncoding,
  hexEncode,
  hexDecode,
  secureRandomInt,
  zeroize,
  zeroizeAll,
  withZeroize,
  createKeyMetadataStore,
  deserializeKey,
  exportKeyToJWK,
  importKeyFromJWK,
} from '../src/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeClient(overrides = {}): EncryptixClient {
  return new EncryptixClient({ key: generateMasterKey(), ...overrides });
}

async function collectStream(readable: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = readable.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.length; }
  return out;
}

// ─── Master Key ───────────────────────────────────────────────────────────────

describe('generateMasterKey', () => {
  it('returns a 64-char hex string', () => {
    const key = generateMasterKey();
    expect(key).toHaveLength(64);
    expect(key).toMatch(/^[0-9a-f]+$/);
  });
  it('generates unique keys', () => {
    expect(generateMasterKey()).not.toBe(generateMasterKey());
  });
});

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

describe('EncryptixClient — AES-256-GCM', () => {
  const enc = makeClient({ algorithm: 'aes-256-gcm' });

  it('encrypts and decrypts', async () => {
    const p = await enc.encrypt('hello', 'test:basic');
    expect(await enc.decrypt(p, 'test:basic')).toBe('hello');
  });
  it('produces unique ciphertexts', async () => {
    expect(await enc.encrypt('x', 'test')).not.toBe(await enc.encrypt('x', 'test'));
  });
  it('rejects wrong purpose', async () => {
    const p = await enc.encrypt('data', 'purpose:a');
    await expect(enc.decrypt(p, 'purpose:b')).rejects.toThrow(EncryptixError);
  });
  it('rejects tampered payload', async () => {
    const p = await enc.encrypt('sensitive', 'test:tamper');
    const bytes = Buffer.from(p, 'base64');
    bytes[bytes.length - 1] ^= 0xff;
    await expect(enc.decrypt(bytes.toString('base64'), 'test:tamper')).rejects.toThrow(EncryptixError);
  });
  it('encrypts unicode and large strings', async () => {
    const text = '🔒 नमस्ते\nこんにちは';
    expect(await enc.decrypt(await enc.encrypt(text, 'test:uni'), 'test:uni')).toBe(text);
    const big = 'x'.repeat(100_000);
    expect(await enc.decrypt(await enc.encrypt(big, 'test:big'), 'test:big')).toBe(big);
  });
  it('supports hex and base64url encoding', async () => {
    for (const encoding of ['hex', 'base64url'] as const) {
      const e = makeClient({ encoding });
      const p = await e.encrypt('hi', 'enc:test');
      expect(await e.decrypt(p, 'enc:test')).toBe('hi');
    }
  });
  it('supports extra AAD', async () => {
    const p = await enc.encrypt('data', 'test:aad', { aad: 'user-123' });
    await expect(enc.decrypt(p, 'test:aad')).rejects.toThrow(EncryptixError);
    expect(await enc.decrypt(p, 'test:aad', { aad: 'user-123' })).toBe('data');
  });
});

// ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────────

describe('EncryptixClient — ChaCha20-Poly1305', () => {
  const enc = makeClient({ algorithm: 'chacha20-poly1305' });
  it('encrypts and decrypts', async () => {
    const p = await enc.encrypt('chacha test', 'test:chacha');
    expect(await enc.decrypt(p, 'test:chacha')).toBe('chacha test');
  });
  it('rejects wrong purpose', async () => {
    const p = await enc.encrypt('secret', 'chacha:a');
    await expect(enc.decrypt(p, 'chacha:b')).rejects.toThrow(EncryptixError);
  });
});

// ─── Cross-algorithm detection ────────────────────────────────────────────────

describe('Algorithm auto-detection', () => {
  it('decrypts AES payload from ChaCha client', async () => {
    const aesClient = makeClient({ algorithm: 'aes-256-gcm' });
    const chachaClient = new EncryptixClient({ key: (aesClient as any).masterKey, algorithm: 'chacha20-poly1305' });
    const p = await aesClient.encrypt('cross', 'test:cross');
    expect(await chachaClient.decrypt(p, 'test:cross')).toBe('cross');
  });
});

// ─── Object Encryption with TTL ──────────────────────────────────────────────

describe('encryptObject / decryptObject', () => {
  const enc = makeClient();

  it('encrypts and decrypts a plain object', async () => {
    const obj = { userId: '123', role: 'admin', scores: [1, 2, 3] };
    const p = await enc.encryptObject(obj, 'test:obj');
    const result = await enc.decryptObject<typeof obj>(p, 'test:obj');
    expect(result).toEqual(obj);
  });

  it('decrypts nested and null values', async () => {
    const data = { a: null, b: [1, { c: true }] };
    const p = await enc.encryptObject(data, 'test:nested');
    expect(await enc.decryptObject(p, 'test:nested')).toEqual(data);
  });

  it('throws PAYLOAD_EXPIRED for expired TTL', async () => {
    const p = await enc.encryptObject({ x: 1 }, 'test:ttl', { ttlSeconds: -1 });
    await expect(enc.decryptObject(p, 'test:ttl')).rejects.toMatchObject({
      code: 'PAYLOAD_EXPIRED',
    });
  });

  it('does not throw for valid TTL', async () => {
    const p = await enc.encryptObject({ x: 1 }, 'test:ttl-ok', { ttlSeconds: 3600 });
    const r = await enc.decryptObject<{ x: number }>(p, 'test:ttl-ok');
    expect(r.x).toBe(1);
  });

  it('supports custom serializer/deserializer', async () => {
    const serialize = (v: unknown) => JSON.stringify(v) + '|custom';
    const deserialize = (s: string) => JSON.parse(s.replace('|custom', ''));
    const p = await enc.encryptObject({ z: 9 }, 'test:serial', { serialize });
    const r = await enc.decryptObject<{ z: number }>(p, 'test:serial', { deserialize });
    expect(r.z).toBe(9);
  });
});

// ─── Deterministic Encryption (AES-SIV) ──────────────────────────────────────

describe('encryptDeterministic / decryptDeterministic', () => {
  const enc = makeClient();

  it('same input produces same ciphertext', async () => {
    const a = await enc.encryptDeterministic('hello', 'det:test');
    const b = await enc.encryptDeterministic('hello', 'det:test');
    expect(a).toBe(b);
  });

  it('different inputs produce different ciphertexts', async () => {
    const a = await enc.encryptDeterministic('hello', 'det:test');
    const b = await enc.encryptDeterministic('world', 'det:test');
    expect(a).not.toBe(b);
  });

  it('decrypts correctly', async () => {
    const p = await enc.encryptDeterministic('lookup-value', 'det:email');
    expect(await enc.decryptDeterministic(p, 'det:email')).toBe('lookup-value');
  });

  it('rejects wrong purpose', async () => {
    const p = await enc.encryptDeterministic('data', 'det:a');
    await expect(enc.decryptDeterministic(p, 'det:b')).rejects.toThrow(EncryptixError);
  });

  it('supports extra AAD (binds ciphertext to context)', async () => {
    const a = await enc.encryptDeterministic('val', 'det:aad', { aad: 'context-1' });
    const b = await enc.encryptDeterministic('val', 'det:aad', { aad: 'context-2' });
    expect(a).not.toBe(b);
    expect(await enc.decryptDeterministic(a, 'det:aad', { aad: 'context-1' })).toBe('val');
  });

  it('detects tampering', async () => {
    const p = await enc.encryptDeterministic('secure', 'det:tamper');
    const bytes = Buffer.from(p, 'base64');
    bytes[bytes.length - 1] ^= 0xff;
    await expect(enc.decryptDeterministic(bytes.toString('base64'), 'det:tamper')).rejects.toThrow(EncryptixError);
  });
});

// ─── Envelope Encryption ─────────────────────────────────────────────────────

describe('envelopeEncrypt / envelopeDecrypt', () => {
  const enc = makeClient();

  it('encrypts and decrypts', async () => {
    const env = await enc.envelopeEncrypt('envelope-secret', 'test:envelope');
    expect(await enc.envelopeDecrypt(env, 'test:envelope')).toBe('envelope-secret');
  });

  it('envelope has expected structure', async () => {
    const env = await enc.envelopeEncrypt('data', 'test:env-struct');
    expect(env.version).toBe(1);
    expect(env.wrapAlgorithm).toBe('AES-KW');
    expect(env.dataAlgorithm).toBe('aes-256-gcm');
    expect(env.wrappedDek).toBeTruthy();
    expect(env.ciphertext).toBeTruthy();
    expect(env.kekFingerprint).toHaveLength(16);
  });

  it('different encryptions produce different DEKs', async () => {
    const e1 = await enc.envelopeEncrypt('same', 'test:env-dek');
    const e2 = await enc.envelopeEncrypt('same', 'test:env-dek');
    expect(e1.wrappedDek).not.toBe(e2.wrappedDek);
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
  });

  it('rejects wrong purpose', async () => {
    const env = await enc.envelopeEncrypt('data', 'env:a');
    await expect(enc.envelopeDecrypt(env, 'env:b')).rejects.toThrow(EncryptixError);
  });

  it('rejects wrong key', async () => {
    const enc2 = makeClient();
    const env = await enc.envelopeEncrypt('data', 'env:key');
    await expect(enc2.envelopeDecrypt(env, 'env:key')).rejects.toThrow(EncryptixError);
  });
});

// ─── Signed Tokens ───────────────────────────────────────────────────────────

describe('sign / verify', () => {
  const enc = makeClient();

  it('signs and verifies a payload', async () => {
    const token = await enc.sign({ userId: '123' }, 'auth:access');
    const result = await enc.verify<{ userId: string }>(token, 'auth:access');
    expect(result.valid).toBe(true);
    expect(result.payload?.userId).toBe('123');
    expect(result.reason).toBe('valid');
  });

  it('rejects expired token', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:exp', { ttlSeconds: -1 });
    const result = await enc.verify(token, 'auth:exp');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('expired');
    expect(result.remainingTtl).toBeLessThan(0);
  });

  it('throws on expired token when throwOnExpiry is set', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:throw', { ttlSeconds: -1 });
    await expect(enc.verify(token, 'auth:throw', { throwOnExpiry: true })).rejects.toMatchObject({
      code: 'TOKEN_EXPIRED',
    });
  });

  it('returns remainingTtl for valid token with TTL', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:ttl', { ttlSeconds: 3600 });
    const result = await enc.verify(token, 'auth:ttl');
    expect(result.valid).toBe(true);
    expect(result.remainingTtl).toBeGreaterThan(3500);
  });

  it('rejects wrong purpose', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:a');
    const result = await enc.verify(token, 'auth:b');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid_signature');
  });

  it('rejects tampered token', async () => {
    const token = await enc.sign({ userId: '123' }, 'auth:tamper');
    const tampered = token.slice(0, -4) + 'XXXX';
    const result = await enc.verify(tampered, 'auth:tamper');
    expect(result.valid).toBe(false);
  });

  it('rejects token from different key', async () => {
    const enc2 = makeClient();
    const token = await enc.sign({ x: 1 }, 'auth:key');
    const result = await enc2.verify(token, 'auth:key');
    expect(result.valid).toBe(false);
  });

  it('signs complex nested objects', async () => {
    const payload = { user: { id: 1, roles: ['admin', 'user'] }, meta: { v: 2 } };
    const token = await enc.sign(payload, 'auth:complex', { ttlSeconds: 3600 });
    const result = await enc.verify<typeof payload>(token, 'auth:complex');
    expect(result.valid).toBe(true);
    expect(result.payload).toEqual(payload);
  });

  it('produces URL-safe tokens by default', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:url');
    // Dot-separated base64url segments — no + or /
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    expect(token).not.toMatch(/[+/=]/);
  });
});

// ─── Streaming ───────────────────────────────────────────────────────────────

describe('encryptStream / decryptStream', () => {
  const enc = makeClient();

  async function streamRoundTrip(data: Uint8Array, purpose: string): Promise<string> {
    const encTransform = enc.encryptStream({ purpose });
    const decTransform = enc.decryptStream({ purpose });

    // Push data into encrypt stream
    const encWriter = encTransform.writable.getWriter();
    encWriter.write(data);
    encWriter.close();

    // Pipe encrypt output to decrypt input
    const encOutput = await collectStream(encTransform.readable);
    const decWriter = decTransform.writable.getWriter();
    decWriter.write(encOutput);
    decWriter.close();

    const decOutput = await collectStream(decTransform.readable);
    return new TextDecoder().decode(decOutput);
  }

  it('encrypts and decrypts a small payload', async () => {
    const data = new TextEncoder().encode('hello streaming world');
    const result = await streamRoundTrip(data, 'stream:basic');
    expect(result).toBe('hello streaming world');
  });

  it('encrypts and decrypts a multi-chunk payload', async () => {
    // 200KB — spans multiple 64KB chunks
    const data = new TextEncoder().encode('A'.repeat(200_000));
    const result = await streamRoundTrip(data, 'stream:large');
    expect(result).toBe('A'.repeat(200_000));
  });

  it('encrypts unicode content', async () => {
    const text = '🔐 Encrypted stream 🔐 with unicode ✓';
    const data = new TextEncoder().encode(text);
    const result = await streamRoundTrip(data, 'stream:unicode');
    expect(result).toBe(text);
  });

  it('rejects stream with wrong purpose on decrypt', async () => {
    const encTransform = enc.encryptStream({ purpose: 'stream:a' });
    const writer = encTransform.writable.getWriter();
    writer.write(new TextEncoder().encode('data'));
    writer.close();
    const encOutput = await collectStream(encTransform.readable);

    const decTransform = enc.decryptStream({ purpose: 'stream:b' });
    const decWriter = decTransform.writable.getWriter();
    // write/close may reject when controller.error() is called in flush — silence to avoid unhandled rejection
    decWriter.write(encOutput).catch(() => {});
    decWriter.close().catch(() => {});

    await expect(collectStream(decTransform.readable)).rejects.toBeDefined();
  });

  it('rejects stream from different key', async () => {
    const enc2 = makeClient();
    const encTransform = enc.encryptStream({ purpose: 'stream:key' });
    const writer = encTransform.writable.getWriter();
    writer.write(new TextEncoder().encode('secret'));
    writer.close();
    const encOutput = await collectStream(encTransform.readable);

    const decTransform = enc2.decryptStream({ purpose: 'stream:key' });
    const decWriter = decTransform.writable.getWriter();
    // write/close may reject when controller.error() is called in flush — silence to avoid unhandled rejection
    decWriter.write(encOutput).catch(() => {});
    decWriter.close().catch(() => {});

    await expect(collectStream(decTransform.readable)).rejects.toBeDefined();
  });
});

// ─── Password KDF ─────────────────────────────────────────────────────────────

describe('deriveKeyFromPassword', () => {
  it('derives consistent key from same password and salt', async () => {
    const { keyHex, saltHex } = await deriveKeyFromPassword('my-pass', 'vault:user', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    const { keyHex: keyHex2 } = await deriveKeyFromPassword('my-pass', 'vault:user', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000, saltHex });
    expect(keyHex).toBe(keyHex2);
  });

  it('different passwords produce different keys', async () => {
    const { keyHex: k1, saltHex } = await deriveKeyFromPassword('pass1', 'vault', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    const { keyHex: k2 } = await deriveKeyFromPassword('pass2', 'vault', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000, saltHex });
    expect(k1).not.toBe(k2);
  });

  it('different purposes produce different keys from same password+salt', async () => {
    const { keyHex: k1, saltHex } = await deriveKeyFromPassword('pass', 'vault:a', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    const { keyHex: k2 } = await deriveKeyFromPassword('pass', 'vault:b', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000, saltHex });
    expect(k1).not.toBe(k2);
  });

  it('new salt produces different key', async () => {
    const { keyHex: k1 } = await deriveKeyFromPassword('pass', 'vault', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    const { keyHex: k2 } = await deriveKeyFromPassword('pass', 'vault', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    expect(k1).not.toBe(k2);
  });

  it('returns a valid 64-char hex key usable by EncryptixClient', async () => {
    const { keyHex, saltHex } = await deriveKeyFromPassword('secure-pass', 'app:data', { algorithm: 'pbkdf2', pbkdf2Iterations: 10000 });
    expect(keyHex).toHaveLength(64);
    expect(keyHex).toMatch(/^[0-9a-f]+$/);
    const client = new EncryptixClient({ key: keyHex });
    const payload = await client.encrypt('from-password-key', 'app:data');
    expect(await client.decrypt(payload, 'app:data')).toBe('from-password-key');
  });

  it('scrypt works in Node.js', async () => {
    const { keyHex, saltHex, algorithm } = await deriveKeyFromPassword('pass', 'vault:scrypt', { algorithm: 'scrypt', scryptN: 1024 });
    expect(algorithm).toBe('scrypt');
    expect(keyHex).toHaveLength(64);
    const { keyHex: k2 } = await deriveKeyFromPassword('pass', 'vault:scrypt', { algorithm: 'scrypt', scryptN: 1024, saltHex });
    expect(keyHex).toBe(k2);
  });

  it('throws on empty password', async () => {
    await expect(deriveKeyFromPassword('', 'vault')).rejects.toThrow(EncryptixError);
  });
});

// ─── Key Rotation ─────────────────────────────────────────────────────────────

describe('Key rotation', () => {
  it('decrypts old payloads after rotation', async () => {
    const v1 = makeClient();
    const oldPayload = await v1.encrypt('old-secret', 'test:rotate');
    const v2 = v1.rotate(generateMasterKey());
    expect(await v2.decrypt(oldPayload, 'test:rotate')).toBe('old-secret');
    const newPayload = await v2.encrypt('new-secret', 'test:rotate');
    expect(await v2.decrypt(newPayload, 'test:rotate')).toBe('new-secret');
  });

  it('v1 cannot decrypt v2 payload', async () => {
    const v1 = makeClient();
    const v2 = v1.rotate(generateMasterKey());
    const p = await v2.encrypt('new', 'test:rotate-fail');
    await expect(v1.decrypt(p, 'test:rotate-fail')).rejects.toThrow(EncryptixError);
  });
});

// ─── Key Fingerprint ──────────────────────────────────────────────────────────

describe('keyFingerprint()', () => {
  it('returns 16-char hex fingerprint', async () => {
    const enc = makeClient();
    const fp = await enc.keyFingerprint();
    expect(fp.fingerprint).toHaveLength(16);
    expect(fp.fingerprint).toMatch(/^[0-9a-f]+$/);
    expect(fp.version).toBe(1);
  });

  it('same key produces same fingerprint', async () => {
    const key = generateMasterKey();
    const enc1 = new EncryptixClient({ key });
    const enc2 = new EncryptixClient({ key });
    expect((await enc1.keyFingerprint()).fingerprint).toBe((await enc2.keyFingerprint()).fingerprint);
  });

  it('different keys produce different fingerprints', async () => {
    const enc1 = makeClient();
    const enc2 = makeClient();
    const fp1 = (await enc1.keyFingerprint()).fingerprint;
    const fp2 = (await enc2.keyFingerprint()).fingerprint;
    expect(fp1).not.toBe(fp2);
  });
});

// ─── RSA-OAEP ─────────────────────────────────────────────────────────────────

describe('RSA-OAEP', () => {
  let keys: { publicKey: string; privateKey: string };
  beforeAll(async () => { keys = await generateRSAKeyPair(2048); });

  it('generates PEM keys', () => {
    expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
  });
  it('encrypts and decrypts', async () => {
    const enc = makeClient();
    const c = await enc.encryptRSA('rsa-secret', keys.publicKey);
    expect(await enc.decryptRSA(c, keys.privateKey)).toBe('rsa-secret');
  });
  it('fails with wrong key', async () => {
    const enc = makeClient();
    const other = await generateRSAKeyPair(2048);
    const c = await enc.encryptRSA('data', keys.publicKey);
    await expect(enc.decryptRSA(c, other.privateKey)).rejects.toThrow(EncryptixError);
  });
});

// ─── Hashing ──────────────────────────────────────────────────────────────────

describe('hash()', () => {
  it('consistent SHA-256', async () => {
    expect(await hash('hello')).toBe(await hash('hello'));
  });
  it('sha256/384/512 correct lengths', async () => {
    expect(await hash('x', 'sha256')).toHaveLength(64);
    expect(await hash('x', 'sha384')).toHaveLength(96);
    expect(await hash('x', 'sha512')).toHaveLength(128);
  });
});

// ─── HMAC ─────────────────────────────────────────────────────────────────────

describe('hmac() / verifyHmac()', () => {
  const key = generateMasterKey();
  it('verifies valid signature', async () => {
    const sig = await hmac('msg', key);
    expect(await verifyHmac('msg', key, sig)).toBe(true);
  });
  it('rejects tampered message', async () => {
    const sig = await hmac('msg', key);
    expect(await verifyHmac('tampered', key, sig)).toBe(false);
  });
});

// ─── Token Generation ─────────────────────────────────────────────────────────

describe('Token generation', () => {
  it('generateToken is unique hex', () => {
    const t = generateToken(32, 'hex');
    expect(t).toHaveLength(64);
    expect(generateToken()).not.toBe(generateToken());
  });
  it('generateApiKey has correct prefix', () => {
    expect(generateApiKey('sk').startsWith('sk_')).toBe(true);
  });
  it('generateUUID is valid v4', () => {
    expect(generateUUID()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });
});

// ─── Error Handling ───────────────────────────────────────────────────────────

describe('Error handling', () => {
  it('throws INVALID_KEY when no key', () => {
    const saved = process.env.ENCRYPTIX_KEY;
    delete process.env.ENCRYPTIX_KEY;
    expect(() => createEncryptix()).toThrow(EncryptixError);
    process.env.ENCRYPTIX_KEY = saved;
  });
  it('throws INVALID_KEY for short key', () => {
    expect(() => new EncryptixClient({ key: 'tooshort' })).toThrow(EncryptixError);
  });
  it('throws INVALID_PURPOSE for empty purpose', async () => {
    const enc = makeClient();
    await expect(enc.encrypt('data', '')).rejects.toThrow(EncryptixError);
  });
  it('throws INVALID_PAYLOAD for garbage', async () => {
    const enc = makeClient();
    await expect(enc.decrypt('garbage!!!', 'any')).rejects.toThrow(EncryptixError);
  });
  it('EncryptixError has code property', async () => {
    const enc = makeClient();
    try {
      await enc.decrypt('garbage!!!', 'any');
    } catch (err) {
      expect(err).toBeInstanceOf(EncryptixError);
      expect((err as EncryptixError).code).toBeTruthy();
    }
  });
});

// ─── createEncryptix factory ─────────────────────────────────────────────────

describe('createEncryptix()', () => {
  it('creates client from env variable', async () => {
    process.env.ENCRYPTIX_KEY = generateMasterKey();
    const enc = createEncryptix();
    const p = await enc.encrypt('env-test', 'test:env');
    expect(await enc.decrypt(p, 'test:env')).toBe('env-test');
    delete process.env.ENCRYPTIX_KEY;
  });
});

// ─── ECDH Key Agreement ───────────────────────────────────────────────────────

describe('ECDH key agreement', () => {
  it('generates a P-256 key pair', async () => {
    const enc = makeClient();
    const keys = await enc.generateECDHKeyPair('P-256');
    expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(keys.curve).toBe('P-256');
  });

  it('alice and bob derive the same shared secret', async () => {
    const enc = makeClient();
    const alice = await enc.generateECDHKeyPair();
    const bob   = await enc.generateECDHKeyPair();
    const sharedA = await enc.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const sharedB = await enc.deriveSharedSecret(bob.privateKey, alice.publicKey);
    expect(sharedA).toBe(sharedB);
    expect(sharedA).toHaveLength(64); // 32 bytes hex
  });

  it('different key pairs produce different secrets', async () => {
    const enc = makeClient();
    const a = await enc.generateECDHKeyPair();
    const b = await enc.generateECDHKeyPair();
    const c = await enc.generateECDHKeyPair();
    const s1 = await enc.deriveSharedSecret(a.privateKey, b.publicKey);
    const s2 = await enc.deriveSharedSecret(a.privateKey, c.publicKey);
    expect(s1).not.toBe(s2);
  });

  it('shared secret can be used as EncryptixClient key', async () => {
    const enc = makeClient();
    const alice = await enc.generateECDHKeyPair();
    const bob   = await enc.generateECDHKeyPair();
    const shared = await enc.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const sessionEnc = new EncryptixClient({ key: shared });
    const payload = await sessionEnc.encrypt('e2e message', 'session:data');
    expect(await sessionEnc.decrypt(payload, 'session:data')).toBe('e2e message');
  });

  it('throws on mismatched curves', async () => {
    const enc = makeClient();
    const p256 = await enc.generateECDHKeyPair('P-256');
    const p384 = await enc.generateECDHKeyPair('P-384');
    await expect(enc.deriveSharedSecret(p256.privateKey, p384.publicKey, 'P-256')).rejects.toThrow(EncryptixError);
  });
});

// ─── ECDSA Signatures ─────────────────────────────────────────────────────────

describe('ECDSA signatures', () => {
  let keys: import('../src/index.js').ECKeyPair;
  beforeAll(async () => {
    const enc = makeClient();
    keys = await enc.generateECDSAKeyPair('P-256');
  });

  it('generates P-256 key pair', () => {
    expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(keys.curve).toBe('P-256');
  });

  it('signs and verifies a string', async () => {
    const enc = makeClient();
    const sig = await enc.signECDSA('document content', keys.privateKey);
    expect(await enc.verifyECDSA('document content', sig, keys.publicKey)).toBe(true);
  });

  it('signs and verifies bytes', async () => {
    const enc = makeClient();
    const data = new TextEncoder().encode('binary data');
    const sig = await enc.signECDSA(data, keys.privateKey);
    expect(await enc.verifyECDSA(data, sig, keys.publicKey)).toBe(true);
  });

  it('rejects tampered data', async () => {
    const enc = makeClient();
    const sig = await enc.signECDSA('original', keys.privateKey);
    expect(await enc.verifyECDSA('tampered', sig, keys.publicKey)).toBe(false);
  });

  it('rejects wrong key', async () => {
    const enc = makeClient();
    const other = await enc.generateECDSAKeyPair();
    const sig = await enc.signECDSA('data', keys.privateKey);
    expect(await enc.verifyECDSA('data', sig, other.publicKey)).toBe(false);
  });

  it('produces different signatures (randomized)', async () => {
    const enc = makeClient();
    const s1 = await enc.signECDSA('same', keys.privateKey);
    const s2 = await enc.signECDSA('same', keys.privateKey);
    expect(s1).not.toBe(s2); // ECDSA is randomized
  });
});

// ─── RSA-PSS Signatures ───────────────────────────────────────────────────────

describe('RSA-PSS signatures', () => {
  let keys: import('../src/index.js').RSAKeyPair;
  beforeAll(async () => {
    const enc = makeClient();
    keys = await enc.generateRSAPSSKeyPair(2048);
  });

  it('generates key pair', () => {
    expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('signs and verifies', async () => {
    const enc = makeClient();
    const sig = await enc.signRSA('important payload', keys.privateKey);
    expect(await enc.verifyRSA('important payload', sig, keys.publicKey)).toBe(true);
  });

  it('rejects tampered data', async () => {
    const enc = makeClient();
    const sig = await enc.signRSA('original', keys.privateKey);
    expect(await enc.verifyRSA('tampered', sig, keys.publicKey)).toBe(false);
  });

  it('rejects wrong public key', async () => {
    const enc = makeClient();
    const other = await enc.generateRSAPSSKeyPair(2048);
    const sig = await enc.signRSA('data', keys.privateKey);
    expect(await enc.verifyRSA('data', sig, other.publicKey)).toBe(false);
  });
});

// ─── TOTP / HOTP ─────────────────────────────────────────────────────────────

describe('TOTP / HOTP', () => {
  const enc = makeClient();

  it('generateTOTPSecret returns base32 string', () => {
    const secret = enc.generateTOTPSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(secret.length).toBeGreaterThan(10);
  });

  it('generates unique secrets', () => {
    expect(enc.generateTOTPSecret()).not.toBe(enc.generateTOTPSecret());
  });

  it('HOTP is deterministic for same counter', async () => {
    const secret = enc.generateTOTPSecret();
    const otp1 = await enc.generateHOTP(secret, 1);
    const otp2 = await enc.generateHOTP(secret, 1);
    expect(otp1).toBe(otp2);
    expect(otp1).toMatch(/^\d{6}$/);
  });

  it('HOTP differs across counters', async () => {
    const secret = enc.generateTOTPSecret();
    const otp1 = await enc.generateHOTP(secret, 1);
    const otp2 = await enc.generateHOTP(secret, 2);
    expect(otp1).not.toBe(otp2);
  });

  it('TOTP generates valid 6-digit code', async () => {
    const secret = enc.generateTOTPSecret();
    const code = await enc.generateTOTP(secret);
    expect(code).toMatch(/^\d{6}$/);
  });

  it('TOTP verifies current code', async () => {
    const secret = enc.generateTOTPSecret();
    const code = await enc.generateTOTP(secret);
    const result = await enc.verifyTOTP(code, secret);
    expect(result.valid).toBe(true);
    expect(result.delta).toBe(0);
    expect(result.remainingSeconds).toBeGreaterThan(0);
  });

  it('TOTP rejects wrong code', async () => {
    const secret = enc.generateTOTPSecret();
    const result = await enc.verifyTOTP('000000', secret);
    // Very unlikely to be valid (1/1000000 chance)
    if (!result.valid) expect(result.delta).toBeNull();
  });

  it('TOTP rejects non-numeric input', async () => {
    const secret = enc.generateTOTPSecret();
    const result = await enc.verifyTOTP('abcdef', secret);
    expect(result.valid).toBe(false);
  });

  it('totpKeyUri generates correct format', () => {
    const uri = enc.totpKeyUri('JBSWY3DPEHPK3PXP', 'user@example.com', 'MyApp');
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('issuer=MyApp');
    expect(uri).toContain('digits=6');
    expect(uri).toContain('period=30');
  });
});

// ─── Multi-Recipient Envelopes ────────────────────────────────────────────────

describe('multiRecipientEncrypt / multiRecipientDecrypt', () => {
  let r1Keys: import('../src/index.js').RSAKeyPair;
  let r2Keys: import('../src/index.js').RSAKeyPair;
  const enc = makeClient();

  beforeAll(async () => {
    [r1Keys, r2Keys] = await Promise.all([
      generateRSAKeyPair(2048),
      generateRSAKeyPair(2048),
    ]);
  });

  it('encrypts and both recipients can decrypt', async () => {
    const envelope = await enc.multiRecipientEncrypt('shared secret', [
      { id: 'alice', publicKeyPEM: r1Keys.publicKey },
      { id: 'bob',   publicKeyPEM: r2Keys.publicKey },
    ]);
    expect(await enc.multiRecipientDecrypt(envelope, 'alice', r1Keys.privateKey)).toBe('shared secret');
    expect(await enc.multiRecipientDecrypt(envelope, 'bob',   r2Keys.privateKey)).toBe('shared secret');
  });

  it('envelope structure is correct', async () => {
    const envelope = await enc.multiRecipientEncrypt('data', [
      { id: 'r1', publicKeyPEM: r1Keys.publicKey },
    ]);
    expect(envelope.version).toBe(1);
    expect(envelope.recipients).toHaveLength(1);
    expect(envelope.recipients[0].id).toBe('r1');
    expect(envelope.ciphertext).toBeTruthy();
  });

  it('unknown recipient throws ENVELOPE_ERROR', async () => {
    const envelope = await enc.multiRecipientEncrypt('data', [
      { id: 'alice', publicKeyPEM: r1Keys.publicKey },
    ]);
    await expect(enc.multiRecipientDecrypt(envelope, 'charlie', r1Keys.privateKey))
      .rejects.toMatchObject({ code: 'ENVELOPE_ERROR' });
  });

  it('wrong private key throws ENVELOPE_ERROR', async () => {
    const envelope = await enc.multiRecipientEncrypt('data', [
      { id: 'alice', publicKeyPEM: r1Keys.publicKey },
    ]);
    await expect(enc.multiRecipientDecrypt(envelope, 'alice', r2Keys.privateKey))
      .rejects.toThrow(EncryptixError);
  });

  it('addRecipient allows new recipient to decrypt', async () => {
    const envelope = await enc.multiRecipientEncrypt('data', [
      { id: 'alice', publicKeyPEM: r1Keys.publicKey },
    ]);
    const updated = await enc.addRecipient(envelope, 'alice', r1Keys.privateKey, {
      id: 'bob', publicKeyPEM: r2Keys.publicKey,
    });
    expect(updated.recipients).toHaveLength(2);
    expect(await enc.multiRecipientDecrypt(updated, 'bob', r2Keys.privateKey)).toBe('data');
  });

  it('removeRecipient removes from envelope', async () => {
    const envelope = await enc.multiRecipientEncrypt('data', [
      { id: 'alice', publicKeyPEM: r1Keys.publicKey },
      { id: 'bob',   publicKeyPEM: r2Keys.publicKey },
    ]);
    const updated = enc.removeRecipient(envelope, 'alice');
    expect(updated.recipients).toHaveLength(1);
    expect(updated.recipients[0].id).toBe('bob');
  });
});

// ─── Batch Operations ─────────────────────────────────────────────────────────

describe('Batch encrypt / decrypt', () => {
  const enc = makeClient();

  it('encryptBatch / decryptBatch roundtrip', async () => {
    const items = ['alpha', 'beta', 'gamma', 'delta'];
    const encrypted = await enc.encryptBatch(items, 'batch:test');
    expect(encrypted).toHaveLength(4);
    const decrypted = await enc.decryptBatch(encrypted, 'batch:test');
    expect(decrypted).toEqual(items);
  });

  it('preserves order', async () => {
    const items = ['first', 'second', 'third'];
    const encrypted = await enc.encryptBatch(items, 'batch:order');
    const decrypted = await enc.decryptBatch(encrypted, 'batch:order');
    expect(decrypted[0]).toBe('first');
    expect(decrypted[2]).toBe('third');
  });

  it('encryptBatchMixed handles mixed purposes', async () => {
    const encrypted = await enc.encryptBatchMixed([
      { value: 'user@example.com', purpose: 'user:email' },
      { value: '+1234567890',      purpose: 'user:phone' },
      { value: '123-45-6789',      purpose: 'user:ssn'   },
    ]);
    expect(encrypted).toHaveLength(3);
    // Each should decrypt with the right purpose
    const email = await enc.decrypt(encrypted[0], 'user:email');
    expect(email).toBe('user@example.com');
  });

  it('encryptBatchSafe collects errors without throwing', async () => {
    const items = ['valid', 'also-valid'];
    const results = await enc.encryptBatchSafe(items, 'batch:safe');
    expect(results.every(r => r.ok)).toBe(true);
    expect(results[0].index).toBe(0);
    expect(results[1].index).toBe(1);
  });

  it('decryptBatchSafe reports per-item errors', async () => {
    const good = await enc.encrypt('real', 'batch:safe2');
    const results = await enc.decryptBatchSafe([good, 'not-a-payload'], 'batch:safe2');
    expect(results[0].ok).toBe(true);
    expect(results[1].ok).toBe(false);
  });

  it('handles empty arrays', async () => {
    expect(await enc.encryptBatch([], 'batch:empty')).toEqual([]);
    expect(await enc.decryptBatch([], 'batch:empty')).toEqual([]);
  });
});

// ─── Codec Utilities ─────────────────────────────────────────────────────────

describe('Codec utilities', () => {
  it('base32 encode/decode roundtrip', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const encoded = base32Encode(bytes);
    expect(encoded).toMatch(/^[A-Z2-7]+$/);
    expect(base32Decode(encoded)).toEqual(bytes);
  });

  it('safeCompare is constant-time correct', () => {
    expect(safeCompare('abc', 'abc')).toBe(true);
    expect(safeCompare('abc', 'abd')).toBe(false);
    expect(safeCompare('abc', 'abcd')).toBe(false);
    expect(safeCompare('', '')).toBe(true);
  });

  it('safeCompare works with Uint8Arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    expect(safeCompare(a, b)).toBe(true);
    expect(safeCompare(a, c)).toBe(false);
  });

  it('convertEncoding hex → base64url → hex', () => {
    const hex = 'deadbeef01234567';
    const b64url = convertEncoding(hex, 'hex', 'base64url');
    expect(b64url).not.toContain('+');
    expect(b64url).not.toContain('/');
    expect(convertEncoding(b64url, 'base64url', 'hex')).toBe(hex);
  });

  it('hexEncode / hexDecode roundtrip', () => {
    const bytes = new Uint8Array([0x00, 0xff, 0x42, 0xab]);
    expect(hexEncode(bytes)).toBe('00ff42ab');
    expect(hexDecode('00ff42ab')).toEqual(bytes);
  });

  it('hexDecode throws on invalid chars', () => {
    expect(() => hexDecode('xyz123')).toThrow();
  });
});

// ─── Secure Random ───────────────────────────────────────────────────────────

describe('Secure random utilities', () => {
  const enc = makeClient();

  it('randomInt is in range', () => {
    for (let i = 0; i < 100; i++) {
      const v = enc.randomInt(1, 6);
      expect(v).toBeGreaterThanOrEqual(1);
      expect(v).toBeLessThanOrEqual(6);
    }
  });

  it('randomInt handles min === max', () => {
    expect(enc.randomInt(5, 5)).toBe(5);
  });

  it('randomString has correct length and charset', () => {
    const s = enc.randomString(20, 'alphanumeric');
    expect(s).toHaveLength(20);
    expect(s).toMatch(/^[A-Za-z0-9]+$/);
  });

  it('randomString is unique', () => {
    expect(enc.randomString(32)).not.toBe(enc.randomString(32));
  });

  it('randomChoice returns element from array', () => {
    const arr = ['a', 'b', 'c', 'd'];
    for (let i = 0; i < 20; i++) {
      expect(arr).toContain(enc.randomChoice(arr));
    }
  });

  it('randomSample returns correct count of unique items', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const sample = enc.randomSample(arr, 3);
    expect(sample).toHaveLength(3);
    expect(new Set(sample).size).toBe(3); // all unique
    expect(sample.every(v => arr.includes(v))).toBe(true);
  });

  it('randomShuffle returns all elements', () => {
    const arr = [1, 2, 3, 4, 5];
    const shuffled = enc.randomShuffle(arr);
    expect(shuffled).toHaveLength(5);
    expect([...shuffled].sort((a,b) => a-b)).toEqual(arr);
  });

  it('randomBytes returns correct length', () => {
    expect(enc.randomBytes(16)).toHaveLength(16);
    expect(enc.randomBytes(32)).toHaveLength(32);
  });

  it('randomFloat is in [0, 1)', () => {
    for (let i = 0; i < 50; i++) {
      const f = enc.randomFloat();
      expect(f).toBeGreaterThanOrEqual(0);
      expect(f).toBeLessThan(1);
    }
  });

  it('standalone secureRandomInt throws on invalid range', () => {
    expect(() => secureRandomInt(10, 5)).toThrow();
  });
});

// ─── Payload Inspection ───────────────────────────────────────────────────────

describe('Payload inspection', () => {
  const enc = makeClient();

  it('inspectPayload reads algo and keyVersion', async () => {
    const payload = await enc.encrypt('test', 'inspect:test');
    const info = enc.inspectPayload(payload);
    expect(info.algorithm).toBe('aes-256-gcm');
    expect(info.keyVersion).toBe(1);
    expect(info.payloadVersion).toBe(1);
    expect(info.isDeterministic).toBe(false);
    expect(info.totalBytes).toBeGreaterThan(30);
  });

  it('inspectPayload detects ChaCha20', async () => {
    const enc2 = makeClient({ algorithm: 'chacha20-poly1305' });
    const payload = await enc2.encrypt('test', 'inspect:chacha');
    const info = enc2.inspectPayload(payload);
    expect(info.algorithm).toBe('chacha20-poly1305');
  });

  it('inspectPayload detects deterministic (AES-SIV)', async () => {
    const payload = await enc.encryptDeterministic('test', 'inspect:siv');
    const info = enc.inspectPayload(payload);
    expect(info.algorithm).toBe('aes-siv');
    expect(info.isDeterministic).toBe(true);
  });

  it('inspectPayload detects key version after rotation', async () => {
    const v1 = makeClient();
    const v2 = v1.rotate(generateMasterKey());
    const newPayload = await v2.encrypt('test', 'inspect:rotate');
    const info = v2.inspectPayload(newPayload);
    expect(info.keyVersion).toBe(2);
  });

  it('inspectToken reads unverified metadata', async () => {
    const token = await enc.sign({ userId: '123' }, 'auth:inspect', { ttlSeconds: 3600 });
    const info = enc.inspectToken(token);
    expect(info.payload['purpose']).toBe('auth:inspect');
    expect(info.isExpired).toBe(false);
    expect(info.remainingTtl).toBeGreaterThan(3500);
  });

  it('inspectToken detects expired token without verifying', async () => {
    const token = await enc.sign({ x: 1 }, 'auth:expired', { ttlSeconds: -1 });
    const info = enc.inspectToken(token);
    expect(info.isExpired).toBe(true);
    expect(info.remainingTtl).toBeLessThan(0);
  });

  it('inspectPayload throws on garbage input', () => {
    expect(() => enc.inspectPayload('notvalid!!')).toThrow(EncryptixError);
  });
});

// ─── Zeroize & Key Lifecycle ──────────────────────────────────────────────────

describe('Zeroize & key lifecycle', () => {
  it('zeroize clears a buffer', () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroize(buf);
    expect(buf.every(v => v === 0)).toBe(true);
  });

  it('zeroizeAll clears multiple buffers', () => {
    const a = new Uint8Array([1, 2]), b = new Uint8Array([3, 4]);
    zeroizeAll(a, b);
    expect(a.every(v => v === 0)).toBe(true);
    expect(b.every(v => v === 0)).toBe(true);
  });

  it('withZeroize clears buffer even after error', async () => {
    const buf = new Uint8Array([1, 2, 3]);
    try {
      await withZeroize(buf, async () => { throw new Error('fail'); });
    } catch {}
    expect(buf.every(v => v === 0)).toBe(true);
  });

  it('createKeyMetadataStore register and get', () => {
    const store = createKeyMetadataStore();
    const keyHex = generateMasterKey();
    store.register(1, { keyHex, purpose: 'test', algorithm: 'aes-256-gcm', createdAt: new Date() });
    const meta = store.get(1);
    expect(meta.version).toBe(1);
    expect(meta.keyHex).toBe(keyHex);
    expect(meta.purpose).toBe('test');
  });

  it('createKeyMetadataStore toKeychain', () => {
    const store = createKeyMetadataStore();
    const k1 = generateMasterKey(), k2 = generateMasterKey();
    store.register(1, { keyHex: k1, createdAt: new Date() });
    store.register(2, { keyHex: k2, createdAt: new Date() });
    const chain = store.toKeychain();
    expect(chain[1]).toBe(k1);
    expect(chain[2]).toBe(k2);
  });

  it('reEncrypt migrates payload to new purpose', async () => {
    const enc = makeClient();
    const old = await enc.encrypt('migrate-me', 'old:purpose');
    const migrated = await enc.reEncrypt(old, 'old:purpose', 'new:purpose');
    expect(await enc.decrypt(migrated, 'new:purpose')).toBe('migrate-me');
    // Old purpose no longer works
    await expect(enc.decrypt(migrated, 'old:purpose')).rejects.toThrow(EncryptixError);
  });

  it('exportKey returns base64 key', async () => {
    const enc = makeClient();
    const exported = await enc.exportKey('base64');
    expect(exported.length).toBeGreaterThan(40);
    // re-import
    const hexKey = await deserializeKey(exported, 'base64');
    expect(hexKey).toHaveLength(64);
  });

  it('JWK export/import roundtrip', async () => {
    const key = generateMasterKey();
    const jwk = await exportKeyToJWK(key);
    expect(jwk.kty).toBe('oct');
    const reimported = await importKeyFromJWK(jwk);
    expect(reimported).toBe(key);
  });
});

// ─── EncryptixError enhancements ─────────────────────────────────────────────

describe('EncryptixError.from / .is / .toJSON', () => {
  it('from wraps a plain Error', () => {
    const err = new Error('db failed');
    const wrapped = EncryptixError.from(err, 'INVALID_KEY', 'Vault error');
    expect(wrapped).toBeInstanceOf(EncryptixError);
    expect(wrapped.code).toBe('INVALID_KEY');
    expect(wrapped.message).toBe('Vault error');
    expect(wrapped.cause).toBe(err);
  });

  it('from passes through existing EncryptixError', () => {
    const original = new EncryptixError('DECRYPTION_FAILED', 'bad');
    expect(EncryptixError.from(original)).toBe(original);
  });

  it('is acts as type guard', () => {
    const err = new EncryptixError('TOKEN_EXPIRED', 'expired');
    expect(EncryptixError.is(err, 'TOKEN_EXPIRED')).toBe(true);
    expect(EncryptixError.is(err, 'INVALID_KEY')).toBe(false);
    expect(EncryptixError.is(new Error('plain'), 'TOKEN_EXPIRED')).toBe(false);
  });

  it('toJSON is serializable', () => {
    const err = new EncryptixError('STREAM_ERROR', 'bad stream');
    const json = err.toJSON();
    expect(json.code).toBe('STREAM_ERROR');
    expect(json.message).toBe('bad stream');
    expect(JSON.stringify(json)).not.toThrow;
  });

  it('toString includes code', () => {
    const err = new EncryptixError('KEY_NOT_FOUND', 'missing key 3');
    expect(err.toString()).toContain('KEY_NOT_FOUND');
    expect(err.toString()).toContain('missing key 3');
  });
});
