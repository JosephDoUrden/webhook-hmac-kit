import { afterEach, describe, expect, it, vi } from 'vitest';
import { toHex, utf8 } from '../src/bytes.js';
import { buildCanonicalBytes } from '../src/canonical.js';
import { blindedEqual, getSubtle, hmacSha256, importHmacKey } from '../src/crypto.js';
import { TEST_SECRET, vectors } from './vectors.js';

describe('getSubtle', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the ambient SubtleCrypto', () => {
    expect(getSubtle()).toBe(globalThis.crypto.subtle);
  });

  it('reads the global on every call rather than capturing it once', () => {
    const first = getSubtle();
    expect(getSubtle()).toBe(first);
  });

  // There is no polyfill and no dynamic import to fall back to, so the whole value of the guard is
  // in what it says. A caller on a flagged Node build has to be able to fix it from the message.
  it('names itself, the remedy and the flag when the global is missing', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
      expect(() => getSubtle()).toThrow(/Web Crypto/);
      expect(() => getSubtle()).toThrow(
        /globalThis\.crypto \?\?= require\('node:crypto'\)\.webcrypto/,
      );
      expect(() => getSubtle()).toThrow(/--no-experimental-global-webcrypto/);

      let name: string | undefined;
      try {
        getSubtle();
      } catch (error) {
        name = (error as Error).name;
      }
      expect(name).toBe('WebCryptoUnavailableError');
    } finally {
      Object.defineProperty(globalThis, 'crypto', original as PropertyDescriptor);
    }
  });

  it('is equally unhappy when crypto exists without subtle', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true });
    try {
      expect(() => getSubtle()).toThrow(/--no-experimental-global-webcrypto/);
    } finally {
      Object.defineProperty(globalThis, 'crypto', original as PropertyDescriptor);
    }
  });
});

describe('hmacSha256', () => {
  for (const vector of vectors) {
    it(`reproduces the pinned digest for: ${vector.name}`, async () => {
      const canonical = buildCanonicalBytes(vector.timestamp, vector.nonce, vector.payload);
      const digest = await hmacSha256(utf8(TEST_SECRET), canonical);
      expect(toHex(digest)).toBe(vector.signature.slice('v2='.length));
    });
  }

  it('returns 32 bytes as a plain Uint8Array', async () => {
    const digest = await hmacSha256(utf8(TEST_SECRET), utf8('x'));
    expect(digest).toHaveLength(32);
    expect(digest.constructor).toBe(Uint8Array);
  });

  it('separates keys that UTF-8 decoding would collapse', async () => {
    const a = await hmacSha256(Uint8Array.from([0xff]), utf8('x'));
    const b = await hmacSha256(Uint8Array.from([0xfe]), utf8('x'));
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('importHmacKey', () => {
  it('produces a key that can both sign and verify', async () => {
    const key = await importHmacKey(utf8(TEST_SECRET));
    const subtle = getSubtle();
    const signature = await subtle.sign('HMAC', key, utf8('x'));

    // A key imported with usages ['sign'] alone makes subtle.verify throw on every runtime.
    await expect(subtle.verify('HMAC', key, signature, utf8('x'))).resolves.toBe(true);
  });

  it('is not extractable', async () => {
    const key = await importHmacKey(utf8(TEST_SECRET));
    expect(key.extractable).toBe(false);
  });

  // Web Crypto rejects a zero-length key with a DataError on every runtime. normalizeSecrets keeps
  // that from ever arriving here, but the layer should not pretend otherwise.
  it('refuses a zero-length key, as the spec requires', async () => {
    await expect(importHmacKey(new Uint8Array(0))).rejects.toThrow();
  });
});

describe('blindedEqual', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const digest = (fill: number) => new Uint8Array(32).fill(fill);

  it('is true for identical bytes', async () => {
    await expect(blindedEqual(digest(0xab), digest(0xab))).resolves.toBe(true);
  });

  it('is false for a single differing byte', async () => {
    const other = digest(0xab);
    other[31] = 0xac;
    await expect(blindedEqual(digest(0xab), other)).resolves.toBe(false);
  });

  it('is false for a first-byte difference too', async () => {
    const other = digest(0xab);
    other[0] = 0x00;
    await expect(blindedEqual(digest(0xab), other)).resolves.toBe(false);
  });

  it('is false for different lengths', async () => {
    await expect(blindedEqual(digest(0xab), new Uint8Array(16).fill(0xab))).resolves.toBe(false);
  });

  it('is true for two empty runs', async () => {
    await expect(blindedEqual(new Uint8Array(0), new Uint8Array(0))).resolves.toBe(true);
  });

  // Two signs, no verify: the fold is done here rather than handed to subtle.verify, so the call
  // count a verify makes is a flat multiple of the secret count and stays easy to assert on.
  it('signs twice and verifies nothing', async () => {
    const subtle = getSubtle();
    const sign = vi.spyOn(subtle, 'sign');
    const verify = vi.spyOn(subtle, 'verify');

    await blindedEqual(digest(1), digest(1));

    expect(sign).toHaveBeenCalledTimes(2);
    expect(verify).not.toHaveBeenCalled();
  });

  // HMAC generateKey needs an IoContext on Workers and throws outside a request; getRandomValues is
  // the only synchronous member of the Crypto interface and is present everywhere.
  it('draws its blinding key from getRandomValues, never generateKey', async () => {
    const subtle = getSubtle();
    const generateKey = vi.spyOn(subtle, 'generateKey');
    const getRandomValues = vi.spyOn(globalThis.crypto, 'getRandomValues');

    await blindedEqual(digest(1), digest(2));

    expect(generateKey).not.toHaveBeenCalled();
    expect(getRandomValues).toHaveBeenCalledTimes(1);
    expect(getRandomValues.mock.calls[0]?.[0]).toHaveLength(32);
  });

  it('uses a fresh blinding key per call', async () => {
    const getRandomValues = vi.spyOn(globalThis.crypto, 'getRandomValues');

    await blindedEqual(digest(1), digest(1));
    await blindedEqual(digest(1), digest(1));

    expect(getRandomValues).toHaveBeenCalledTimes(2);
    const [first, second] = getRandomValues.mock.results.map((r) => toHex(r.value as Uint8Array));
    expect(first).not.toBe(second);
  });
});
