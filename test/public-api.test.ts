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
    expect(api.formatSignature(Buffer.alloc(32))).toBe(`v2=${'00'.repeat(32)}`);
    expect(api.formatSignature).toHaveLength(1);
  });
});
