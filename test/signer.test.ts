import { describe, expect, it } from 'vitest';
import { signWebhook } from '../src/signer.js';
import { TEST_SECRET, vectors } from './vectors.js';

describe('signWebhook', () => {
  for (const vector of vectors) {
    it(`produces expected signature for: ${vector.name}`, () => {
      const result = signWebhook({
        secrets: TEST_SECRET,
        payload: vector.payload,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
      });
      expect(result.signature).toBe(vector.signature);
    });
  }

  it('emits the scheme version and a lower-case hex digest on the wire', () => {
    const { signature } = signWebhook({
      secrets: TEST_SECRET,
      payload: 'test',
      timestamp: 1000,
      nonce: 'n',
    });
    expect(signature).toMatch(/^v2=[0-9a-f]{64}$/);
  });

  it('rejects empty secret', () => {
    expect(() =>
      signWebhook({
        secrets: '',
        payload: 'test',
        timestamp: 1000,
        nonce: 'n',
      }),
    ).toThrow('secrets must not be empty');
  });

  it('rejects a nonce outside the v2 grammar', () => {
    for (const nonce of ['', 'a.b', 'a:b', 'x'.repeat(65)]) {
      expect(() =>
        signWebhook({ secrets: TEST_SECRET, payload: 'test', timestamp: 1000, nonce }),
      ).toThrow(/nonce/);
    }
  });

  it('rejects a non-integer or negative timestamp', () => {
    for (const timestamp of [1000.5, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() =>
        signWebhook({ secrets: TEST_SECRET, payload: 'test', timestamp, nonce: 'n' }),
      ).toThrow(/timestamp/);
    }
  });

  it('is deterministic: same inputs produce same output', () => {
    const opts = {
      secrets: TEST_SECRET,
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
    const a = signWebhook({ ...opts, secrets: 'secret-a' });
    const b = signWebhook({ ...opts, secrets: 'secret-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different payload', () => {
    const opts = { secrets: TEST_SECRET, timestamp: 1000, nonce: 'n' };
    const a = signWebhook({ ...opts, payload: 'payload-a' });
    const b = signWebhook({ ...opts, payload: 'payload-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different timestamp', () => {
    const opts = { secrets: TEST_SECRET, payload: 'test', nonce: 'n' };
    const a = signWebhook({ ...opts, timestamp: 1000 });
    const b = signWebhook({ ...opts, timestamp: 2000 });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different nonce', () => {
    const opts = { secrets: TEST_SECRET, payload: 'test', timestamp: 1000 };
    const a = signWebhook({ ...opts, nonce: 'nonce-a' });
    const b = signWebhook({ ...opts, nonce: 'nonce-b' });
    expect(a.signature).not.toBe(b.signature);
  });
});

// The signed value is bytes, not a JS string. UTF-8 encoding collapses every unpaired surrogate to
// the same three bytes, so a string-only payload type cannot carry a body that is not UTF-8 text.
describe('signWebhook with byte inputs', () => {
  const timestamp = 1000;
  const nonce = 'n';

  it('signs a string payload and its UTF-8 bytes identically', () => {
    const payload = '{"name":"Héllo Wörld","emoji":"🚀"}';
    const asText = signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce });
    const asBytes = signWebhook({
      secrets: TEST_SECRET,
      payload: Buffer.from(payload, 'utf8'),
      timestamp,
      nonce,
    });
    expect(asBytes.signature).toBe(asText.signature);
  });

  it('distinguishes byte payloads that UTF-8 decoding would collapse', () => {
    const opts = { secrets: TEST_SECRET, timestamp, nonce };
    const a = signWebhook({ ...opts, payload: Uint8Array.from([0x7b, 0xff, 0x7d]) });
    const b = signWebhook({ ...opts, payload: Uint8Array.from([0x7b, 0xfe, 0x7d]) });
    expect(a.signature).not.toBe(b.signature);
  });

  it('signs with a string secret and its UTF-8 bytes identically', () => {
    const opts = { payload: 'test', timestamp, nonce };
    const asText = signWebhook({ ...opts, secrets: TEST_SECRET });
    const asBytes = signWebhook({ ...opts, secrets: Buffer.from(TEST_SECRET, 'utf8') });
    expect(asBytes.signature).toBe(asText.signature);
  });

  it('distinguishes binary secrets that UTF-8 decoding would collapse', () => {
    const opts = { payload: 'test', timestamp, nonce };
    const a = signWebhook({ ...opts, secrets: Uint8Array.from([0xff]) });
    const b = signWebhook({ ...opts, secrets: Uint8Array.from([0xfe]) });
    expect(a.signature).not.toBe(b.signature);
  });
});
