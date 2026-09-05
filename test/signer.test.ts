import { describe, expect, it } from 'vitest';
import { utf8 } from '../src/bytes.js';
import { signWebhook } from '../src/signer.js';
import { TEST_SECRET, vectors } from './vectors.js';

describe('signWebhook', () => {
  for (const vector of vectors) {
    it(`produces expected signature for: ${vector.name}`, async () => {
      const result = await signWebhook({
        secrets: TEST_SECRET,
        payload: vector.payload,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
      });
      expect(result.signature).toBe(vector.signature);
    });
  }

  it('emits the scheme version and a lower-case hex digest on the wire', async () => {
    const { signature } = await signWebhook({
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
    ).toThrow('each secret must be a non-empty string or byte array');
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

  it('is deterministic: same inputs produce same output', async () => {
    const opts = {
      secrets: TEST_SECRET,
      payload: 'determinism',
      timestamp: 1000,
      nonce: 'n',
    };
    const a = await signWebhook(opts);
    const b = await signWebhook(opts);
    expect(a.signature).toBe(b.signature);
  });

  it('produces different signature with different secret', async () => {
    const opts = { payload: 'test', timestamp: 1000, nonce: 'n' };
    const a = await signWebhook({ ...opts, secrets: 'secret-a' });
    const b = await signWebhook({ ...opts, secrets: 'secret-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different payload', async () => {
    const opts = { secrets: TEST_SECRET, timestamp: 1000, nonce: 'n' };
    const a = await signWebhook({ ...opts, payload: 'payload-a' });
    const b = await signWebhook({ ...opts, payload: 'payload-b' });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different timestamp', async () => {
    const opts = { secrets: TEST_SECRET, payload: 'test', nonce: 'n' };
    const a = await signWebhook({ ...opts, timestamp: 1000 });
    const b = await signWebhook({ ...opts, timestamp: 2000 });
    expect(a.signature).not.toBe(b.signature);
  });

  it('produces different signature with different nonce', async () => {
    const opts = { secrets: TEST_SECRET, payload: 'test', timestamp: 1000 };
    const a = await signWebhook({ ...opts, nonce: 'nonce-a' });
    const b = await signWebhook({ ...opts, nonce: 'nonce-b' });
    expect(a.signature).not.toBe(b.signature);
  });
});

// The signed value is bytes, not a JS string. UTF-8 encoding collapses every unpaired surrogate to
// the same three bytes, so a string-only payload type cannot carry a body that is not UTF-8 text.
describe('signWebhook with byte inputs', () => {
  const timestamp = 1000;
  const nonce = 'n';

  it('signs a string payload and its UTF-8 bytes identically', async () => {
    const payload = '{"name":"Héllo Wörld","emoji":"🚀"}';
    const asText = await signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce });
    const asBytes = await signWebhook({
      secrets: TEST_SECRET,
      payload: utf8(payload),
      timestamp,
      nonce,
    });
    expect(asBytes.signature).toBe(asText.signature);
  });

  it('distinguishes byte payloads that UTF-8 decoding would collapse', async () => {
    const opts = { secrets: TEST_SECRET, timestamp, nonce };
    const a = await signWebhook({ ...opts, payload: Uint8Array.from([0x7b, 0xff, 0x7d]) });
    const b = await signWebhook({ ...opts, payload: Uint8Array.from([0x7b, 0xfe, 0x7d]) });
    expect(a.signature).not.toBe(b.signature);
  });

  it('signs with a string secret and its UTF-8 bytes identically', async () => {
    const opts = { payload: 'test', timestamp, nonce };
    const asText = await signWebhook({ ...opts, secrets: TEST_SECRET });
    const asBytes = await signWebhook({ ...opts, secrets: utf8(TEST_SECRET) });
    expect(asBytes.signature).toBe(asText.signature);
  });

  it('distinguishes binary secrets that UTF-8 decoding would collapse', async () => {
    const opts = { payload: 'test', timestamp, nonce };
    const a = await signWebhook({ ...opts, secrets: Uint8Array.from([0xff]) });
    const b = await signWebhook({ ...opts, secrets: Uint8Array.from([0xfe]) });
    expect(a.signature).not.toBe(b.signature);
  });
});

describe('signWebhook payload type guard', () => {
  for (const payload of [['a'], null, {}, undefined]) {
    it(`refuses to sign ${JSON.stringify(payload) ?? 'undefined'}`, () => {
      expect(() =>
        signWebhook({
          secrets: TEST_SECRET,
          payload: payload as string,
          timestamp: 1000,
          nonce: 'n',
        }),
      ).toThrow(/payload/);
    });
  }
});
