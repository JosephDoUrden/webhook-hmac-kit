import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { toHex, utf8 } from '../src/bytes.js';
import { buildCanonicalBytes } from '../src/canonical.js';
import {
  blindMany,
  blindedEqual,
  blindedFoldEqual,
  getSubtle,
  hmacSha256,
  importHmacKey,
} from '../src/crypto.js';
import { TEST_SECRET, vectors } from './vectors.js';

/**
 * Matches a module specifier, not the mention of one: getSubtle's remedy message shows the ESM
 * form of the node:crypto import as example text for the reader to copy, and that text is not a
 * specifier this file itself resolves.
 */
const NODE_SPECIFIER = /(?:\bfrom|\bimport)\s*\(?\s*['"]node:/;

/**
 * The one line the scan below has to ignore. Stripping just this line, rather than loosening
 * NODE_SPECIFIER, keeps the check able to catch a real import added anywhere else in src.
 */
const REMEDY_EXAMPLE_LINE = /importing this library first: import/;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return path.endsWith('.ts') ? [path] : [];
  });
}

describe('src imports nothing from Node', () => {
  // A literal 'node:...' specifier is resolved at bundle time by esbuild, wrangler, Vite and Metro
  // whether or not the code around it can run, so a try/catch does not make one safe: octokit's
  // React Native consumers got "Unable to resolve module node:crypto" from exactly this shape.
  // Enforced here rather than trusted, because nothing else in the toolchain would notice.
  it('has no node: specifier in any source file', () => {
    // fileURLToPath rather than .pathname, which would leave percent-encoding in the path.
    const src = fileURLToPath(new URL('../src/', import.meta.url));
    const offenders = sourceFiles(src)
      .filter((file) => {
        const content = readFileSync(file, 'utf8')
          .split('\n')
          .filter((line) => !REMEDY_EXAMPLE_LINE.test(line))
          .join('\n');
        return NODE_SPECIFIER.test(content);
      })
      .map((file) => file.slice(src.length));

    expect(offenders).toEqual([]);
  });
});

describe('getSubtle', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the ambient SubtleCrypto', () => {
    expect(getSubtle()).toBe(globalThis.crypto.subtle);
  });

  // Not a style point. On Workers the module body runs outside a request, so a SubtleCrypto
  // captured at import time belongs to an isolate that may already be gone by the time a request
  // uses it. The only way to show the value is re-read is to change it underneath and look.
  it('reads the global on every call rather than capturing it once', () => {
    const real = getSubtle();
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const standIn = { subtle: { imposter: true } };

    Object.defineProperty(globalThis, 'crypto', { value: standIn, configurable: true });
    try {
      expect(getSubtle()).toBe(standIn.subtle);
      expect(getSubtle()).not.toBe(real);
    } finally {
      Object.defineProperty(globalThis, 'crypto', original as PropertyDescriptor);
    }

    expect(getSubtle()).toBe(real);
  });

  // There is no polyfill and no dynamic import to fall back to, so the whole value of the guard is
  // in what it says. A caller on a flagged Node build has to be able to fix it from the message.
  it('names itself, the remedy and the flag when the global is missing', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
      expect(() => getSubtle()).toThrow(/Web Crypto/);
      // ESM is the form a caller in this "type": "module" package actually needs; the CommonJS
      // form is still named, in one clause, for a caller importing this library from CJS.
      expect(() => getSubtle()).toThrow(
        /import \{ webcrypto \} from 'node:crypto'; globalThis\.crypto \?\?= webcrypto/,
      );
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

describe('blindMany', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const digest = (fill: number) => new Uint8Array(32).fill(fill);

  it('returns one 32-byte value per input, in order', async () => {
    const blinded = await blindMany([digest(1), digest(2), digest(3)]);

    expect(blinded).toHaveLength(3);
    for (const value of blinded) {
      expect(value.constructor).toBe(Uint8Array);
      expect(value).toHaveLength(32);
    }
  });

  // The whole point of the primitive: one key covers the whole batch, so a verify that compares s
  // expected MACs against e presented digests costs s + e signs instead of 2 * s * e.
  it('draws one blinding key however many inputs there are', async () => {
    const subtle = getSubtle();
    const sign = vi.spyOn(subtle, 'sign');
    const importKey = vi.spyOn(subtle, 'importKey');
    const getRandomValues = vi.spyOn(globalThis.crypto, 'getRandomValues');

    await blindMany([digest(1), digest(2), digest(3), digest(4), digest(5)]);

    expect(sign).toHaveBeenCalledTimes(5);
    expect(importKey).toHaveBeenCalledTimes(1);
    expect(getRandomValues).toHaveBeenCalledTimes(1);
    expect(getRandomValues.mock.calls[0]?.[0]).toHaveLength(32);
  });

  it('does not reach for generateKey', async () => {
    const generateKey = vi.spyOn(getSubtle(), 'generateKey');
    await blindMany([digest(1)]);
    expect(generateKey).not.toHaveBeenCalled();
  });

  // Equality has to survive the blind within one batch, and inequality has to survive it too.
  // Without both, the fold that follows would be comparing noise.
  it('preserves equality and inequality inside one batch', async () => {
    const [a, b, c] = await blindMany([digest(7), digest(7), digest(8)]);

    expect(blindedFoldEqual(a as Uint8Array, b as Uint8Array)).toBe(true);
    expect(blindedFoldEqual(a as Uint8Array, c as Uint8Array)).toBe(false);
  });

  // Operands blinded under different keys are not comparable, which is why the verifier blinds the
  // expected MACs and the presented digests in a single call rather than one call each.
  it('gives a different result for the same input on a second call', async () => {
    const [first] = await blindMany([digest(9)]);
    const [second] = await blindMany([digest(9)]);

    expect(blindedFoldEqual(first as Uint8Array, second as Uint8Array)).toBe(false);
  });

  it('hides the input rather than passing it through', async () => {
    const [blinded] = await blindMany([digest(0)]);
    expect(blindedFoldEqual(blinded as Uint8Array, digest(0))).toBe(false);
  });

  it('handles an empty batch without drawing a key it cannot use', async () => {
    await expect(blindMany([])).resolves.toEqual([]);
  });
});

describe('blindedFoldEqual', () => {
  it('compares contents', () => {
    expect(blindedFoldEqual(new Uint8Array(32).fill(5), new Uint8Array(32).fill(5))).toBe(true);
    expect(blindedFoldEqual(new Uint8Array(32).fill(5), new Uint8Array(32).fill(6))).toBe(false);
  });

  it('treats different lengths as unequal without saying which was longer', () => {
    expect(blindedFoldEqual(new Uint8Array(32), new Uint8Array(16))).toBe(false);
    expect(blindedFoldEqual(new Uint8Array(16), new Uint8Array(32))).toBe(false);
  });

  it('does not confuse a prefix with the whole', () => {
    const long = new Uint8Array(32).fill(1);
    const short = new Uint8Array(16).fill(1);
    expect(blindedFoldEqual(long, short)).toBe(false);
  });
});
