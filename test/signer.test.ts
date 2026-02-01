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

  it('uses v1 as default version', () => {
    const withDefault = signWebhook({
      secret: TEST_SECRET,
      payload: 'test',
      timestamp: 1000,
      nonce: 'n',
    });
    const withExplicit = signWebhook({
      secret: TEST_SECRET,
      payload: 'test',
      timestamp: 1000,
      nonce: 'n',
      version: 'v1',
    });
    expect(withDefault.signature).toBe(withExplicit.signature);
  });

  it('produces different signature with custom version', () => {
    const v1 = signWebhook({
      secret: TEST_SECRET,
      payload: 'test',
      timestamp: 1000,
      nonce: 'n',
      version: 'v1',
    });
    const v2 = signWebhook({
      secret: TEST_SECRET,
      payload: 'test',
      timestamp: 1000,
      nonce: 'n',
      version: 'v2',
    });
    expect(v1.signature).not.toBe(v2.signature);
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
