import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from '../src/bytes.js';
import { getSubtle } from '../src/crypto.js';
import { WebhookSignatureError } from '../src/errors.js';
import { normalizeSecrets } from '../src/secrets.js';
import { signWebhook } from '../src/signer.js';
import { verifyWebhook } from '../src/verifier.js';
import { TEST_SECRET, TEST_TIMESTAMP } from './vectors.js';

const OLD_SECRET = 'whsec_old_secret_key_0000000000';
const payload = '{"event":"rotation"}';
const nonce = 'rotation_nonce_1';

describe('secret rotation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('signs with the first secret in the list', async () => {
    const list = await signWebhook({
      secrets: [TEST_SECRET, OLD_SECRET],
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    const single = await signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    expect(list.signature).toBe(single.signature);
  });

  it('verifies when the matching secret is not the first one', async () => {
    const { signature } = await signWebhook({
      secrets: OLD_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    await expect(
      verifyWebhook({
        secrets: [TEST_SECRET, OLD_SECRET],
        payload,
        signature,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it('verifies when the matching secret is the first one', async () => {
    const { signature } = await signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    await expect(
      verifyWebhook({
        secrets: [TEST_SECRET, OLD_SECRET],
        payload,
        signature,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it('rejects when no secret in the list matches', async () => {
    const { signature } = await signWebhook({
      secrets: 'whsec_retired_key',
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    await expect(
      verifyWebhook({
        secrets: [TEST_SECRET, OLD_SECRET],
        payload,
        signature,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).rejects.toThrow(WebhookSignatureError);
  });

  // The work a verify does must depend on how many secrets are configured and on nothing else. It
  // is three signs per secret - one expected MAC, then two more to blind that MAC and the presented
  // digest under a throwaway key - and no verify at all, since the fold is done in blindedEqual.
  // Whether the match is at the front, the middle, the end or nowhere makes no difference.
  const ROTATION = [TEST_SECRET, OLD_SECRET, 'whsec_third'];

  it.each([
    ['the first', ROTATION[0] as string],
    ['a middle', ROTATION[1] as string],
    ['the last', ROTATION[2] as string],
    ['no', 'whsec_retired_key'],
  ])('does the same work when %s secret matches', async (_which, signingSecret) => {
    const { signature } = await signWebhook({
      secrets: signingSecret,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    const subtle = getSubtle();
    const sign = vi.spyOn(subtle, 'sign');
    const verify = vi.spyOn(subtle, 'verify');

    await verifyWebhook({
      secrets: ROTATION,
      payload,
      signature,
      timestamp: TEST_TIMESTAMP,
      nonce,
    }).catch(() => undefined);

    expect(sign).toHaveBeenCalledTimes(3 * ROTATION.length);
    expect(verify).not.toHaveBeenCalled();
  });

  it('still rejects when none of them matches', async () => {
    await expect(
      verifyWebhook({
        secrets: ROTATION,
        payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).rejects.toThrow(WebhookSignatureError);
  });

  it('rejects an empty list', async () => {
    expect(() => signWebhook({ secrets: [], payload, timestamp: TEST_TIMESTAMP, nonce })).toThrow(
      'secrets must not be empty',
    );

    await expect(
      verifyWebhook({
        secrets: [],
        payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).rejects.toThrow('secrets must not be empty');
  });

  it('names the entry problem rather than calling the list empty', async () => {
    expect(() =>
      signWebhook({ secrets: [TEST_SECRET, ''], payload, timestamp: TEST_TIMESTAMP, nonce }),
    ).toThrow('each secret must be a non-empty string or byte array');

    await expect(
      verifyWebhook({
        secrets: ['', TEST_SECRET],
        payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).rejects.toThrow('each secret must be a non-empty string or byte array');
  });

  it('distinguishes an empty list from an unusable entry', () => {
    expect(() => normalizeSecrets([])).toThrow('secrets must not be empty');
    expect(() => normalizeSecrets([TEST_SECRET, new Uint8Array(0)])).toThrow(
      'each secret must be a non-empty string or byte array',
    );
    expect(() => normalizeSecrets([TEST_SECRET, 42 as unknown as string])).toThrow(
      'each secret must be a non-empty string or byte array',
    );
  });
});

describe('secret list hygiene', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('evaluates a repeated secret once', async () => {
    const { signature } = await signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    const sign = vi.spyOn(getSubtle(), 'sign');

    await verifyWebhook({
      secrets: [TEST_SECRET, TEST_SECRET, OLD_SECRET, TEST_SECRET],
      payload,
      signature,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    // Two distinct secrets out of four entries, so six signs and not twelve.
    expect(sign).toHaveBeenCalledTimes(6);
  });

  it('treats a string secret and its UTF-8 bytes as the same entry', () => {
    expect(normalizeSecrets([TEST_SECRET, utf8(TEST_SECRET)])).toHaveLength(1);
  });

  it('rejects more distinct secrets than a rotation could need', () => {
    const many = Array.from({ length: 17 }, (_, i) => `whsec_${i}`);
    expect(() => normalizeSecrets(many)).toThrow(/more than 16/);
    expect(() => normalizeSecrets(many.slice(0, 16))).not.toThrow();
  });

  it('counts duplicates once against the cap', () => {
    const many = Array.from({ length: 40 }, () => TEST_SECRET);
    expect(() => normalizeSecrets(many)).not.toThrow();
  });
});
