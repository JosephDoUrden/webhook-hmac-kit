import { describe, expect, it } from 'vitest';
import { buildCanonicalString } from '../src/canonical.js';
import { vectors } from './vectors.js';

describe('buildCanonicalString', () => {
  for (const vector of vectors) {
    it(`produces correct canonical string for: ${vector.name}`, () => {
      const result = buildCanonicalString('v1', vector.timestamp, vector.nonce, vector.payload);
      expect(result).toBe(vector.canonical);
    });
  }

  it('preserves whitespace in payload', () => {
    const result = buildCanonicalString('v1', 1000, 'n', '  spaces  ');
    expect(result).toBe('v1:1000:n:  spaces  ');
  });

  it('handles empty payload', () => {
    const result = buildCanonicalString('v1', 1000, 'n', '');
    expect(result).toBe('v1:1000:n:');
  });

  it('handles unicode in payload', () => {
    const result = buildCanonicalString('v1', 1000, 'n', '\u00e9\ud83d\ude80');
    expect(result).toBe('v1:1000:n:\u00e9\ud83d\ude80');
  });

  it('handles colons in payload without ambiguity', () => {
    const result = buildCanonicalString('v1', 1000, 'n', 'a:b:c');
    expect(result).toBe('v1:1000:n:a:b:c');
  });

  it('uses custom version prefix', () => {
    const result = buildCanonicalString('v2', 1000, 'n', 'body');
    expect(result).toBe('v2:1000:n:body');
  });
});
