/**
 * HMAC key handling, hex parsing, and constant-time comparison.
 */

import { createHmac, randomBytes } from 'node:crypto';
import { EncryptixClient, EncryptixError, generateMasterKey, hmac, verifyHmac } from '../src/index.js';
import { hexToBytes, timingSafeEqual, timingSafeEqualFallback, decodeInput } from '../src/utils/env.js';

const nodeHmac = (alg: string, key: string | Buffer, msg: string | Buffer, enc: 'hex' | 'base64') =>
  createHmac(alg, key).update(msg).digest(enc);

// ─── hexToBytes ─────────────────────────────────────────────────────────────

describe('hexToBytes()', () => {
  it('decodes lower- and uppercase hex', () => {
    expect(Array.from(hexToBytes('00ff7fA0'))).toEqual([0x00, 0xff, 0x7f, 0xa0]);
    expect(hexToBytes('')).toHaveLength(0);
  });

  it.each(['abc', 'f'])('throws on odd length: %p', (input) => {
    expect(() => hexToBytes(input)).toThrow(/length must be even/);
  });

  it.each(['zz', '0g', 'g0', '12 4', ' 1234', '0x12', 'my-secret!', '1é'])(
    'throws on non-hex characters: %p',
    (input) => {
      let err: unknown;
      try { hexToBytes(input); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(EncryptixError);
      expect((err as EncryptixError).code).toBe('CODEC_ERROR');
      expect((err as Error).message).toMatch(/non-hex character|length must be even/);
    },
  );

  it('decodeInput(hex) rejects bad hex instead of yielding zero bytes', () => {
    expect(() => decodeInput('zz', 'hex')).toThrow(EncryptixError);
  });

  it('error message does not echo the offending input', () => {
    expect(() => hexToBytes('supersecretvalue')).toThrow(/position 0/);
    try { hexToBytes('supersecretvalue'); } catch (e) {
      expect((e as Error).message).not.toContain('supersecret');
    }
  });
});

// ─── timingSafeEqual ────────────────────────────────────────────────────────

describe('timingSafeEqual()', () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  it.each([
    ['native/auto', timingSafeEqual],
    ['JS fallback', timingSafeEqualFallback],
  ])('%s: equal, unequal, and length mismatch', (_name, fn) => {
    expect(fn(a, new Uint8Array([1, 2, 3, 4]))).toBe(true);
    expect(fn(a, new Uint8Array([1, 2, 3, 5]))).toBe(false);
    expect(fn(a, new Uint8Array([1, 2, 3]))).toBe(false);
    expect(fn(a, new Uint8Array([1, 2, 3, 4, 0]))).toBe(false);
    expect(fn(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

// ─── RFC 4231 vectors (hex keys, default keyEncoding) ───────────────────────

const RFC4231: Array<{ name: string; key: string; data: string; sha256: string; sha384: string; sha512: string }> = [
  {
    name: 'TC1',
    key: '0b'.repeat(20),
    data: '4869205468657265',
    sha256: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    sha384: 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    sha512: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    name: 'TC2 ("Jefe")',
    key: '4a656665',
    data: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    sha256: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    sha384: 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
    sha512: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    name: 'TC3',
    key: 'aa'.repeat(20),
    data: 'dd'.repeat(50),
    sha256: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    sha384: '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
    sha512: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    name: 'TC6 (131-byte key)',
    key: 'aa'.repeat(131),
    data: '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
    sha256: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    sha384: '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
    sha512: '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
];

describe('hmac() RFC 4231 vectors (hex key)', () => {
  for (const tc of RFC4231) {
    for (const alg of ['sha256', 'sha384', 'sha512'] as const) {
      it(`${tc.name} HMAC-${alg.toUpperCase()}`, async () => {
        const msg = hexToBytes(tc.data);
        // 1.0.0 positional form
        expect(await hmac(msg, tc.key, alg)).toBe(tc[alg]);
        // options form, explicit hex
        expect(await hmac(msg, tc.key, { algorithm: alg, keyEncoding: 'hex' })).toBe(tc[alg]);
        // uppercase hex key gives the same result
        expect(await hmac(msg, tc.key.toUpperCase(), alg)).toBe(tc[alg]);
        // raw-bytes key
        expect(await hmac(msg, hexToBytes(tc.key), alg)).toBe(tc[alg]);
        // cross-check with node
        expect(nodeHmac(alg, Buffer.from(tc.key, 'hex'), Buffer.from(msg), 'hex')).toBe(tc[alg]);
      });
    }
  }
});

// ─── UTF-8 / base64 keys vs node createHmac ─────────────────────────────────

describe('hmac() with plain-text (utf8) secrets', () => {
  const vectors = [
    { secret: 'Jefe', body: 'what do ya want for nothing?' },
    { secret: 'shpss_0123456789abcdef', body: '{"id":820982911946154500,"email":"jon@example.com"}' },
    { secret: 'wc-secret with spaces & ünïcödé ✓', body: 'order.created' },
    { secret: 'deadbeef', body: 'hex-looking secret is still treated as text' },
  ];

  for (const { secret, body } of vectors) {
    for (const alg of ['sha256', 'sha512'] as const) {
      it(`matches createHmac(${alg}) for secret ${JSON.stringify(secret)}`, async () => {
        expect(await hmac(body, secret, { algorithm: alg, keyEncoding: 'utf8' }))
          .toBe(nodeHmac(alg, secret, body, 'hex'));
        expect(await hmac(body, secret, { algorithm: alg, keyEncoding: 'utf8', encoding: 'base64' }))
          .toBe(nodeHmac(alg, secret, body, 'base64'));
      });
    }
  }

  it('RFC 4231 TC2 with the text key "Jefe" equals the hex-key result', async () => {
    const msg = 'what do ya want for nothing?';
    expect(await hmac(msg, 'Jefe', { keyEncoding: 'utf8' })).toBe(RFC4231[1].sha256);
  });

  it('a hex-looking string means different keys under hex vs utf8', async () => {
    const hexRes = await hmac('m', 'deadbeef');
    const utf8Res = await hmac('m', 'deadbeef', { keyEncoding: 'utf8' });
    expect(hexRes).toBe(nodeHmac('sha256', Buffer.from('deadbeef', 'hex'), 'm', 'hex'));
    expect(utf8Res).toBe(nodeHmac('sha256', 'deadbeef', 'm', 'hex'));
    expect(hexRes).not.toBe(utf8Res);
  });

  it('base64 / base64url keys', async () => {
    const raw = randomBytes(32);
    const expected = nodeHmac('sha256', raw, 'payload', 'hex');
    expect(await hmac('payload', raw.toString('base64'), { keyEncoding: 'base64' })).toBe(expected);
    expect(await hmac('payload', raw.toString('base64url'), { keyEncoding: 'base64url' })).toBe(expected);
  });

  it('base64url output matches node', async () => {
    expect(await hmac('x', 'Jefe', { keyEncoding: 'utf8', encoding: 'base64url' }))
      .toBe(createHmac('sha256', 'Jefe').update('x').digest('base64url'));
  });
});

describe('hmac() key validation', () => {
  it('non-hex string with default keyEncoding throws INVALID_KEY (no silent zero key)', async () => {
    await expect(hmac('m', 'my-webhook-secret')).rejects.toMatchObject({ code: 'INVALID_KEY' });
    await expect(hmac('m', 'my-webhook-secret')).rejects.toThrow(/keyEncoding: 'utf8'/);
  });
  it('odd-length hex key throws INVALID_KEY', async () => {
    await expect(hmac('m', 'abc')).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });
  it('empty key throws INVALID_KEY', async () => {
    await expect(hmac('m', '')).rejects.toMatchObject({ code: 'INVALID_KEY' });
    await expect(hmac('m', new Uint8Array(0))).rejects.toMatchObject({ code: 'INVALID_KEY' });
    await expect(hmac('m', '', { keyEncoding: 'utf8' })).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });
  it('invalid base64 key throws INVALID_KEY', async () => {
    await expect(hmac('m', '!!!', { keyEncoding: 'base64' })).rejects.toMatchObject({ code: 'INVALID_KEY' });
  });
});

// ─── verifyHmac ─────────────────────────────────────────────────────────────

describe('verifyHmac()', () => {
  const secret = 'shpss_test_secret';
  const body = '{"order":1}';
  const opts = { keyEncoding: 'utf8', encoding: 'base64' } as const;
  const shopifyHeader = createHmac('sha256', secret).update(body).digest('base64');

  it('accepts a Shopify-style base64 signature', async () => {
    expect(await verifyHmac(body, secret, shopifyHeader, opts)).toBe(true);
  });
  it('accepts Uint8Array bodies (raw request bytes)', async () => {
    expect(await verifyHmac(new TextEncoder().encode(body), secret, shopifyHeader, opts)).toBe(true);
  });
  it('rejects a tampered body', async () => {
    expect(await verifyHmac(body + ' ', secret, shopifyHeader, opts)).toBe(false);
  });
  it('rejects the wrong secret', async () => {
    expect(await verifyHmac(body, secret + 'x', shopifyHeader, opts)).toBe(false);
  });
  it('rejects a flipped signature byte', async () => {
    const bytes = Buffer.from(shopifyHeader, 'base64');
    bytes[0] ^= 1;
    expect(await verifyHmac(body, secret, bytes.toString('base64'), opts)).toBe(false);
  });
  it('returns false on length mismatch (truncated / extended / empty)', async () => {
    const hex = createHmac('sha256', secret).update(body).digest('hex');
    const hexOpts = { keyEncoding: 'utf8' } as const;
    expect(await verifyHmac(body, secret, hex, hexOpts)).toBe(true);
    expect(await verifyHmac(body, secret, hex.slice(0, -2), hexOpts)).toBe(false);
    expect(await verifyHmac(body, secret, hex + '00', hexOpts)).toBe(false);
    expect(await verifyHmac(body, secret, '', hexOpts)).toBe(false);
    // sha512 signature against a sha256 verify
    const sha512 = createHmac('sha512', secret).update(body).digest('hex');
    expect(await verifyHmac(body, secret, sha512, hexOpts)).toBe(false);
  });
  it('returns false (does not throw) for a malformed signature', async () => {
    expect(await verifyHmac(body, secret, 'zz'.repeat(32), { keyEncoding: 'utf8' })).toBe(false);
    expect(await verifyHmac(body, secret, '***', opts)).toBe(false);
  });
  it('hex signatures compare case-insensitively', async () => {
    const key = generateMasterKey();
    const sig = await hmac('msg', key);
    expect(await verifyHmac('msg', key, sig.toUpperCase())).toBe(true);
  });
  it('1.0.0 positional form still works', async () => {
    const key = generateMasterKey();
    const sig = await hmac('msg', key, 'sha512', 'base64');
    expect(await verifyHmac('msg', key, sig, 'sha512', 'base64')).toBe(true);
    expect(await verifyHmac('msg', key, sig, 'sha256', 'base64')).toBe(false);
  });
});

// ─── EncryptixClient ────────────────────────────────────────────────────────

describe('EncryptixClient.hmac / verifyHmac', () => {
  const masterKey = generateMasterKey();
  const enc = new EncryptixClient({ key: masterKey });

  it('falls back to the master key (hex) when no key is passed', async () => {
    const sig = await enc.hmac('body');
    expect(sig).toBe(nodeHmac('sha256', Buffer.from(masterKey, 'hex'), 'body', 'hex'));
    expect(await enc.verifyHmac('body', sig)).toBe(true);
  });

  it('uses an explicit utf8 secret with base64 output', async () => {
    const sig = await enc.hmac('body', 'whsec', { keyEncoding: 'utf8', encoding: 'base64' });
    expect(sig).toBe(nodeHmac('sha256', 'whsec', 'body', 'base64'));
    expect(await enc.verifyHmac('body', sig, 'whsec', { keyEncoding: 'utf8', encoding: 'base64' })).toBe(true);
  });

  it('refuses to fall back to the master key when keyEncoding is set but key is missing', async () => {
    const missing = undefined as string | undefined;
    await expect(enc.hmac('body', missing, { keyEncoding: 'utf8' })).rejects.toMatchObject({ code: 'INVALID_KEY' });
    await expect(enc.verifyHmac('body', 'sig', missing, { keyEncoding: 'utf8' }))
      .rejects.toMatchObject({ code: 'INVALID_KEY' });
  });

  it('uses the client hashAlgorithm by default', async () => {
    const c = new EncryptixClient({ key: masterKey, hashAlgorithm: 'sha512' });
    expect(await c.hmac('body')).toBe(nodeHmac('sha512', Buffer.from(masterKey, 'hex'), 'body', 'hex'));
    expect(await c.hmac('body', 'k', { keyEncoding: 'utf8' })).toBe(nodeHmac('sha512', 'k', 'body', 'hex'));
  });
});
