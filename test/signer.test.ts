import { describe, expect, it } from 'vitest';
import { signWebhook } from '../src/signer.js';
import { TEST_SECRET, vectors } from './vectors.js';

describe('signWebhook', () => {
  for (const vector of vectors) {
    it(`produces expected signature for: ${vector.name}`, () => {
      const result = signWebhook({
        secret: TEST_SECRET,
        payload: vector.payload,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
      });
      expect(result.signature).toBe(vector.signature);
    });
  }

  it('rejects empty secret', () => {
    expect(() =>
      signWebhook({
        secret: '',
        payload: 'test',
        timestamp: 1000,
        nonce: 'n',
      }),
    ).toThrow('secret must not be empty');
  });

  it('rejects a nonce outside the v2 grammar', () => {
    for (const nonce of ['', 'a.b', 'a:b', 'x'.repeat(65)]) {
      expect(() =>
        signWebhook({ secret: TEST_SECRET, payload: 'test', timestamp: 1000, nonce }),
      ).toThrow(/nonce/);
    }
  });

  it('rejects a non-integer or negative timestamp', () => {
    for (const timestamp of [1000.5, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() =>
        signWebhook({ secret: TEST_SECRET, payload: 'test', timestamp, nonce: 'n' }),
      ).toThrow(/timestamp/);
    }
  });

  it('is deterministic: same inputs produce same output', () => {
    const opts = {
      secret: TEST_SECRET,
      payload: 'determinism',
      timestamp: 1000,
      nonce: 'n',
    };
    const a = signWebhook(opts);
    const b = signWebhook(opts);
    expect(a.signature).toBe(b.signature);
  });

  it('produces different signature with different secret', () => {
    const opts = { payload: 'test', timestamp: 1000, nonce: 'n' };
    const a = signWebhook({ ...opts, secret: 'secret-a' });
    const b = signWebhook({ ...opts, secret: 'secret-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different payload', () => {
    const opts = { secret: TEST_SECRET, timestamp: 1000, nonce: 'n' };
    const a = signWebhook({ ...opts, payload: 'payload-a' });
    const b = signWebhook({ ...opts, payload: 'payload-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different timestamp', () => {
    const opts = { secret: TEST_SECRET, payload: 'test', nonce: 'n' };
    const a = signWebhook({ ...opts, timestamp: 1000 });
    const b = signWebhook({ ...opts, timestamp: 2000 });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different nonce', () => {
    const opts = { secret: TEST_SECRET, payload: 'test', timestamp: 1000 };
    const a = signWebhook({ ...opts, nonce: 'nonce-a' });
    const b = signWebhook({ ...opts, nonce: 'nonce-b' });
    expect(a.signature).not.toBe(b.signature);
  });
});
