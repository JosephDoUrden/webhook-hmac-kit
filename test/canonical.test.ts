import { describe, expect, it } from 'vitest';
import {
  NONCE_PATTERN,
  buildCanonicalBytes,
  buildCanonicalString,
  isValidNonce,
  isValidTimestamp,
} from '../src/canonical.js';
import { vectors } from './vectors.js';

describe('buildCanonicalString', () => {
  for (const vector of vectors) {
    it(`produces correct canonical string for: ${vector.name}`, () => {
      const result = buildCanonicalString(vector.timestamp, vector.nonce, vector.payload);
      expect(result).toBe(vector.canonical);
    });
  }

  it('uses the v2 layout: version.timestamp.nonce.payload', () => {
    expect(buildCanonicalString(1000, 'n', 'body')).toBe('v2.1000.n.body');
  });

  it('preserves whitespace in payload', () => {
    expect(buildCanonicalString(1000, 'n', '  spaces  ')).toBe('v2.1000.n.  spaces  ');
  });

  it('handles empty payload', () => {
    expect(buildCanonicalString(1000, 'n', '')).toBe('v2.1000.n.');
  });

  it('handles unicode in payload', () => {
    expect(buildCanonicalString(1000, 'n', 'é🚀')).toBe('v2.1000.n.é🚀');
  });

  it('keeps dots and colons in the payload verbatim', () => {
    expect(buildCanonicalString(1000, 'n', 'a.b:c')).toBe('v2.1000.n.a.b:c');
  });

  it('renders large timestamps in plain decimal, never exponent form', () => {
    const result = buildCanonicalString(Number.MAX_SAFE_INTEGER, 'n', '');
    expect(result).toBe('v2.9007199254740991.n.');
  });

  describe('timestamp validation', () => {
    it.each([0.5, 1700000000.5, -1, Number.NaN, Number.POSITIVE_INFINITY, 1e21])(
      'rejects timestamp %s',
      (timestamp) => {
        expect(() => buildCanonicalString(timestamp, 'n', 'body')).toThrow(/timestamp/);
      },
    );

    it('accepts zero and safe integers', () => {
      expect(() => buildCanonicalString(0, 'n', 'body')).not.toThrow();
      expect(() => buildCanonicalString(Number.MAX_SAFE_INTEGER, 'n', 'body')).not.toThrow();
    });
  });

  describe('nonce validation', () => {
    it.each(['', 'a.b', 'a:b', 'a b', 'a/b', 'a+b', 'é', 'x'.repeat(65)])(
      'rejects nonce %j',
      (nonce) => {
        expect(() => buildCanonicalString(1000, nonce, 'body')).toThrow(/nonce/);
      },
    );

    it.each(['a', 'nonce_abc-123', 'x'.repeat(64), 'A-Z_a-z0-9'])('accepts nonce %j', (nonce) => {
      expect(() => buildCanonicalString(1000, nonce, 'body')).not.toThrow();
    });
  });
});

describe('isValidTimestamp', () => {
  it('accepts non-negative safe integers only', () => {
    expect(isValidTimestamp(0)).toBe(true);
    expect(isValidTimestamp(1700000000)).toBe(true);
    expect(isValidTimestamp(-1)).toBe(false);
    expect(isValidTimestamp(1.5)).toBe(false);
    expect(isValidTimestamp(Number.NaN)).toBe(false);
    expect(isValidTimestamp(2 ** 53)).toBe(false);
  });
});

describe('isValidNonce', () => {
  it('matches the exported NONCE_PATTERN', () => {
    expect(NONCE_PATTERN.source).toBe('^[A-Za-z0-9_-]{1,64}$');
    expect(isValidNonce('ok_1-2')).toBe(true);
    expect(isValidNonce('not.ok')).toBe(false);
  });
});

describe('buildCanonicalBytes', () => {
  for (const vector of vectors) {
    it(`matches the canonical string for: ${vector.name}`, () => {
      const result = buildCanonicalBytes(vector.timestamp, vector.nonce, vector.payload);
      expect(result.equals(Buffer.from(vector.canonical, 'utf8'))).toBe(true);
    });
  }

  it('encodes a string payload as UTF-8', () => {
    expect(buildCanonicalBytes(1000, 'n', 'é🚀')).toEqual(Buffer.from('v2.1000.n.é🚀', 'utf8'));
  });

  it('copies a byte payload verbatim, invalid UTF-8 included', () => {
    const payload = Uint8Array.from([0x7b, 0xff, 0x7d]);
    expect(buildCanonicalBytes(1000, 'n', payload)).toEqual(
      Buffer.concat([Buffer.from('v2.1000.n.', 'utf8'), payload]),
    );
  });

  it('keeps byte payloads distinct where UTF-8 decoding would collapse them', () => {
    const a = buildCanonicalBytes(1000, 'n', Uint8Array.from([0xff]));
    const b = buildCanonicalBytes(1000, 'n', Uint8Array.from([0xfe]));
    expect(a.equals(b)).toBe(false);
  });

  it('validates the timestamp and nonce like the string builder', () => {
    expect(() => buildCanonicalBytes(1.5, 'n', 'body')).toThrow(/timestamp/);
    expect(() => buildCanonicalBytes(1000, 'a.b', 'body')).toThrow(/nonce/);
  });
});

// TypeScript stops these at compile time; a JS caller gets no such help, and a stringified payload
// collides with the string that happens to look the same ('null', '[object Object]', 'a').
describe('payload type guard', () => {
  const rejected: Array<[string, unknown]> = [
    ['an array', ['a']],
    ['null', null],
    ['a plain object', {}],
    ['undefined', undefined],
  ];

  for (const [name, payload] of rejected) {
    it(`buildCanonicalString rejects ${name}`, () => {
      expect(() => buildCanonicalString(1000, 'n', payload as string)).toThrow(TypeError);
      expect(() => buildCanonicalString(1000, 'n', payload as string)).toThrow(/payload/);
    });

    it(`buildCanonicalBytes rejects ${name}`, () => {
      expect(() => buildCanonicalBytes(1000, 'n', payload as string)).toThrow(TypeError);
      expect(() => buildCanonicalBytes(1000, 'n', payload as string)).toThrow(/payload/);
    });
  }

  it('buildCanonicalString rejects bytes, which it cannot render as text', () => {
    const payload = Uint8Array.from([0x61]) as unknown as string;
    expect(() => buildCanonicalString(1000, 'n', payload)).toThrow(/payload/);
  });
});
