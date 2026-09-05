import { afterEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from '../src/bytes.js';
import { getSubtle } from '../src/crypto.js';
import { WebhookError } from '../src/errors.js';
import { signWebhook } from '../src/signer.js';
import { signStandardWebhooks } from '../src/standard-webhooks.js';
import { TEST_SECRET, TEST_TIMESTAMP, vectors } from './vectors.js';

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

/**
 * The verify side already refuses a degenerate primitive. The sign side has to as well, and for a
 * worse reason: a short MAC there does not fail, it ships. `v2=` with eight hex characters, or a
 * `v1,` entry that decodes to nothing, goes out over the wire and is a signature in name only.
 */
describe('a degenerate Web Crypto on the sign path', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    ['empty buffers', 0],
    ['truncated buffers', 16],
    ['oversized buffers', 64],
  ])('refuses to sign when sign returns %s', async (_name, size) => {
    vi.spyOn(getSubtle(), 'sign').mockResolvedValue(new ArrayBuffer(size));

    await expect(
      signWebhook({
        secrets: TEST_SECRET,
        payload: '{"a":1}',
        timestamp: TEST_TIMESTAMP,
        nonce: 'nonce_degenerate',
      }),
    ).rejects.toThrow(/32 bytes/);
  });

  it('refuses to sign a Standard Webhooks message on the same runtime', async () => {
    vi.spyOn(getSubtle(), 'sign').mockResolvedValue(new ArrayBuffer(0));

    await expect(
      signStandardWebhooks({
        secrets: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
        messageId: 'msg_degenerate',
        timestamp: TEST_TIMESTAMP,
        payload: '{"a":1}',
      }),
    ).rejects.toThrow(/32 bytes/);
  });

  // A signer that cannot sign is the machine being broken, not a webhook being rejected. Making it
  // a WebhookError would let an adapter answer 401 for it.
  it('reports a broken runtime rather than a failed verification', async () => {
    vi.spyOn(getSubtle(), 'sign').mockResolvedValue(new ArrayBuffer(0));

    const error = await signWebhook({
      secrets: TEST_SECRET,
      payload: '{"a":1}',
      timestamp: TEST_TIMESTAMP,
      nonce: 'nonce_degenerate',
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(WebhookError);
  });
});
