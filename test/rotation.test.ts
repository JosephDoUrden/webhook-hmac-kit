import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebhookSignatureError } from '../src/errors.js';
import { normalizeSecrets } from '../src/secrets.js';
import { signWebhook } from '../src/signer.js';
import { verifyWebhook } from '../src/verifier.js';
import { TEST_SECRET, TEST_TIMESTAMP } from './vectors.js';

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    createHmac: vi.fn(actual.createHmac),
    timingSafeEqual: vi.fn(actual.timingSafeEqual),
  };
});

import { createHmac, timingSafeEqual } from 'node:crypto';

const OLD_SECRET = 'whsec_old_secret_key_0000000000';
const payload = '{"event":"rotation"}';
const nonce = 'rotation_nonce_1';

describe('secret rotation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
    vi.mocked(createHmac).mockClear();
    vi.mocked(timingSafeEqual).mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('signs with the first secret in the list', () => {
    const list = signWebhook({
      secrets: [TEST_SECRET, OLD_SECRET],
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    const single = signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    expect(list.signature).toBe(single.signature);
  });

  it('verifies when the matching secret is not the first one', async () => {
    const { signature } = signWebhook({
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
    const { signature } = signWebhook({
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
    const { signature } = signWebhook({
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

  it('evaluates every candidate even after the first one matches', async () => {
    const { signature } = signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    vi.mocked(createHmac).mockClear();
    vi.mocked(timingSafeEqual).mockClear();

    await verifyWebhook({
      secrets: [TEST_SECRET, OLD_SECRET, 'whsec_third'],
      payload,
      signature,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    expect(createHmac).toHaveBeenCalledTimes(3);
    expect(timingSafeEqual).toHaveBeenCalledTimes(3);
  });

  it('evaluates every candidate when none matches', async () => {
    await expect(
      verifyWebhook({
        secrets: [TEST_SECRET, OLD_SECRET, 'whsec_third'],
        payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }),
    ).rejects.toThrow(WebhookSignatureError);

    expect(createHmac).toHaveBeenCalledTimes(3);
    expect(timingSafeEqual).toHaveBeenCalledTimes(3);
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
    vi.mocked(createHmac).mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('evaluates a repeated secret once', async () => {
    const { signature } = signWebhook({
      secrets: TEST_SECRET,
      payload,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });
    vi.mocked(createHmac).mockClear();

    await verifyWebhook({
      secrets: [TEST_SECRET, TEST_SECRET, OLD_SECRET, TEST_SECRET],
      payload,
      signature,
      timestamp: TEST_TIMESTAMP,
      nonce,
    });

    expect(createHmac).toHaveBeenCalledTimes(2);
  });

  it('treats a string secret and its UTF-8 bytes as the same entry', () => {
    expect(normalizeSecrets([TEST_SECRET, Buffer.from(TEST_SECRET, 'utf8')])).toHaveLength(1);
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
