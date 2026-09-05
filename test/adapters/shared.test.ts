import { describe, expect, it } from 'vitest';
import { resolveRawBody } from '../../src/adapters/shared.js';
import { signWebhook } from '../../src/signer.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

describe('resolveRawBody', () => {
  it('accepts a Buffer and hands the same bytes back', () => {
    const body = Buffer.from([0x7b, 0xff, 0x7d]);
    expect(resolveRawBody({ body })).toBe(body);
  });

  it('accepts a plain Uint8Array', () => {
    const body = Uint8Array.from([1, 2, 3]);
    expect(resolveRawBody({ body })).toBe(body);
  });

  it('signs a Uint8Array body the same as the Buffer of those bytes', () => {
    const bytes = [1, 2, 3];
    const opts = { secrets: TEST_SECRET, timestamp: TEST_TIMESTAMP, nonce: 'n' };
    const asArray = signWebhook({
      ...opts,
      payload: resolveRawBody({ body: Uint8Array.from(bytes) }),
    });
    const asBuffer = signWebhook({
      ...opts,
      payload: resolveRawBody({ body: Buffer.from(bytes) }),
    });
    expect(asArray.signature).toBe(asBuffer.signature);
  });

  it('accepts a string', () => {
    expect(resolveRawBody({ body: 'raw' })).toBe('raw');
  });

  it('prefers rawBody over a parsed body', () => {
    const rawBody = Uint8Array.from([1, 2, 3]);
    expect(resolveRawBody({ rawBody, body: { parsed: true } })).toBe(rawBody);
  });

  it.each([
    ['an ArrayBuffer', new ArrayBuffer(3)],
    ['a DataView', new DataView(new ArrayBuffer(3))],
    ['a parsed object', {}],
    ['an array', [1, 2, 3]],
    ['nothing at all', undefined],
  ])('refuses %s', (_name, body) => {
    expect(() => resolveRawBody({ body })).toThrow(/raw body/i);
  });
});
