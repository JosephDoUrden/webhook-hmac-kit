import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

describe('public surface', () => {
  it('exports the byte builder and not the string one', () => {
    // buildCanonicalString looks hashable and is not: it is the readable form, and handing it to
    // createHmac is exactly the mistake the v2 work was about. It stays internal, for the test
    // vectors and for anything that needs to show what was signed.
    expect(Object.keys(api)).toContain('buildCanonicalBytes');
    expect(Object.keys(api)).not.toContain('buildCanonicalString');
  });

  it('cannot be asked to format a scheme version it does not implement', () => {
    expect(api.formatSignature(new Uint8Array(32))).toBe(`v2=${'00'.repeat(32)}`);
    expect(api.formatSignature).toHaveLength(1);
  });

  // Nothing on the public surface asks for or hands back a Buffer. The digest a caller parses out
  // of a header has to be usable on a runtime that has never heard of Node.
  it('speaks Uint8Array, not Buffer', () => {
    const parsed = api.parseSignature(`v2=${'ab'.repeat(32)}`);
    expect(parsed?.digest.constructor).toBe(Uint8Array);
    expect(api.normalizeSecrets('whsec_x')[0].constructor).toBe(Uint8Array);
    expect(api.buildCanonicalBytes(1000, 'n', 'x').constructor).toBe(Uint8Array);
  });
});
