/**
 * The behaviour the Web Crypto migration has to preserve, pinned before any of it starts.
 *
 * Every call here is written in await-form, including the ones that are synchronous today. Awaiting
 * a non-promise is legal, so this file is byte-identical before and after signWebhook starts
 * returning a promise — which matters, because a file that has to be edited by the commit it exists
 * to police is not an oracle.
 *
 * The exception is the argument-validation assertions, which stay in `expect(() => ...).toThrow()`
 * form on purpose. signWebhook validates eagerly and returns a promise from a plain function rather
 * than being marked async, so a misconfiguration still throws where the caller can catch it instead
 * of arriving as a rejection nobody is waiting on. That is a decision, not an accident: if this file
 * ever has to change here, the function was marked async and the change is the bug.
 *
 * Digests are not the whole contract. A rewrite that hashed correctly and returned {valid:false}
 * instead of rejecting, or lost the error codes, or moved the nonce check after the HMAC, would pass
 * a vectors-only oracle and break every consumer.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webhookVerifier } from '../src/adapters/express.js';
import {
  WebhookError,
  WebhookNonceError,
  WebhookSignatureError,
  WebhookTimestampError,
} from '../src/errors.js';
import { signWebhook } from '../src/signer.js';
import { verifyWebhook } from '../src/verifier.js';
import { TEST_SECRET, TEST_TIMESTAMP, vectors } from './vectors.js';

const firstVector = vectors[0] as (typeof vectors)[number];

describe('migration oracle: the seven vectors', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  for (const vector of vectors) {
    it(`signs to the pinned digest: ${vector.name}`, async () => {
      const { signature } = await signWebhook({
        secrets: TEST_SECRET,
        payload: vector.payload,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
      });
      expect(signature).toBe(vector.signature);
    });

    it(`verifies the pinned digest: ${vector.name}`, async () => {
      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: vector.payload,
        signature: vector.signature,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
      });
      expect(result).toEqual({ valid: true });
    });
  }
});

describe('migration oracle: failure shape', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // A failure is a rejection. Anything that resolves is a pass, and a caller that only checks the
  // resolved value would treat a forged request as verified.
  it('rejects rather than resolving a falsy result', async () => {
    const outcome = await verifyWebhook({
      secrets: TEST_SECRET,
      payload: firstVector.payload,
      signature: `v2=${'0'.repeat(64)}`,
      timestamp: firstVector.timestamp,
      nonce: firstVector.nonce,
    }).then(
      (value) => ({ resolved: value }),
      (error: unknown) => ({ rejected: error }),
    );

    expect(outcome).not.toHaveProperty('resolved');
    expect((outcome as { rejected: unknown }).rejected).toBeInstanceOf(WebhookSignatureError);
  });

  const cases: Array<{
    name: string;
    options: () => Parameters<typeof verifyWebhook>[0];
    type: typeof WebhookError;
    code: string;
    now?: number;
  }> = [
    {
      name: 'a timestamp that is not a non-negative integer',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: -1,
        nonce: firstVector.nonce,
      }),
      type: WebhookTimestampError,
      code: 'WEBHOOK_TIMESTAMP_INVALID',
    },
    {
      name: 'a timestamp outside the tolerance window',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      }),
      type: WebhookTimestampError,
      code: 'WEBHOOK_TIMESTAMP_EXPIRED',
      now: (TEST_TIMESTAMP + 3600) * 1000,
    },
    {
      name: 'a nonce outside the grammar',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: 'not.a.nonce',
      }),
      type: WebhookNonceError,
      code: 'WEBHOOK_NONCE_INVALID',
    },
    {
      name: 'a signature that is not the wire form',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: 'nonsense',
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      }),
      type: WebhookSignatureError,
      code: 'WEBHOOK_SIGNATURE_INVALID',
    },
    {
      name: 'a well-formed signature that does not match',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      }),
      type: WebhookSignatureError,
      code: 'WEBHOOK_SIGNATURE_INVALID',
    },
    {
      name: 'a nonce the validator has already seen',
      options: () => ({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        nonceValidator: async () => false,
      }),
      type: WebhookNonceError,
      code: 'WEBHOOK_NONCE_REPLAYED',
    },
  ];

  for (const testCase of cases) {
    it(`answers ${testCase.name} with ${testCase.code}`, async () => {
      if (testCase.now !== undefined) {
        vi.setSystemTime(testCase.now);
      }

      const error = await verifyWebhook(testCase.options()).then(
        () => null,
        (thrown: unknown) => thrown,
      );

      expect(error).toBeInstanceOf(testCase.type);
      expect(error).toBeInstanceOf(WebhookError);
      expect(error).toHaveProperty('code', testCase.code);
    });
  }

  // A nonce store that is down must not be reported as a replay with the reason thrown away. The
  // cause is the only thing that tells the integrator's onError which of the two happened.
  it('wraps a nonceValidator failure in WebhookNonceError and keeps the cause', async () => {
    const storeFailure = new Error('nonce store unreachable');

    const error = await verifyWebhook({
      secrets: TEST_SECRET,
      payload: firstVector.payload,
      signature: firstVector.signature,
      timestamp: firstVector.timestamp,
      nonce: firstVector.nonce,
      nonceValidator: async () => {
        throw storeFailure;
      },
    }).then(
      () => null,
      (thrown: unknown) => thrown,
    );

    expect(error).toBeInstanceOf(WebhookNonceError);
    expect(error).toHaveProperty('code', 'WEBHOOK_NONCE_INVALID');
    expect(error).toHaveProperty('cause', storeFailure);
  });

  // Not every failure is a verification failure. A misconfigured option is the caller's bug and has
  // to keep arriving as a plain Error, because the adapters map WebhookError to 401 and everything
  // else to 500. A rewrite that caught too broadly and re-threw WebhookSignatureError would turn a
  // 500 into a 401 and hide the misconfiguration behind a signature that looks rejected.
  it('leaves a configuration error as a plain Error, not a WebhookError', async () => {
    const error = await verifyWebhook({
      secrets: TEST_SECRET,
      payload: firstVector.payload,
      signature: firstVector.signature,
      timestamp: firstVector.timestamp,
      nonce: firstVector.nonce,
      tolerance: Number.NaN,
    }).then(
      () => null,
      (thrown: unknown) => thrown,
    );

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(WebhookError);
    expect(error).toHaveProperty('message', 'tolerance must be a non-negative finite number');
  });
});

describe('migration oracle: check order', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // timestamp -> nonce -> signature syntax -> HMAC -> nonce validator. The order is what keeps the
  // expensive and the I/O-bound checks behind the cheap ones, and it is observable: each step below
  // is broken along with every later one, and the earlier error is the one that comes back.
  it('checks the timestamp before the nonce', async () => {
    vi.setSystemTime((TEST_TIMESTAMP + 3600) * 1000);

    await expect(
      verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: 'nonsense',
        timestamp: firstVector.timestamp,
        nonce: 'not.a.nonce',
      }),
    ).rejects.toBeInstanceOf(WebhookTimestampError);
  });

  it('checks the nonce before the signature syntax', async () => {
    await expect(
      verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: 'nonsense',
        timestamp: firstVector.timestamp,
        nonce: 'not.a.nonce',
      }),
    ).rejects.toBeInstanceOf(WebhookNonceError);
  });

  it('checks the signature syntax before the HMAC', async () => {
    await expect(
      verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: 'nonsense',
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      }),
    ).rejects.toThrow('Webhook signature is malformed');
  });

  it('checks the HMAC before calling the nonce validator', async () => {
    const nonceValidator = vi.fn(async () => true);

    await expect(
      verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: `v2=${'0'.repeat(64)}`,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        nonceValidator,
      }),
    ).rejects.toBeInstanceOf(WebhookSignatureError);

    expect(nonceValidator).not.toHaveBeenCalled();
  });
});

describe('migration oracle: secret validation is ours, not the crypto layer’s', () => {
  // Web Crypto refuses a zero-length key with a DataError, where createHmac quietly signed with it.
  // Neither message helps anyone, so the check stays in front of the crypto layer and keeps saying
  // which of the two mistakes was made. It throws synchronously from signWebhook.
  it('names an unusable entry rather than reporting an empty list', () => {
    expect(() =>
      signWebhook({
        secrets: [TEST_SECRET, ''],
        payload: 'x',
        timestamp: TEST_TIMESTAMP,
        nonce: 'n',
      }),
    ).toThrow('each secret must be a non-empty string or byte array');

    expect(() =>
      signWebhook({ secrets: [], payload: 'x', timestamp: TEST_TIMESTAMP, nonce: 'n' }),
    ).toThrow('secrets must not be empty');

    expect(() =>
      signWebhook({
        secrets: new Uint8Array(0),
        payload: 'x',
        timestamp: TEST_TIMESTAMP,
        nonce: 'n',
      }),
    ).toThrow('each secret must be a non-empty string or byte array');
  });

  it('validates arguments where the caller can catch it', () => {
    expect(() =>
      signWebhook({ secrets: TEST_SECRET, payload: 'x', timestamp: 1.5, nonce: 'n' }),
    ).toThrow(/timestamp/);

    expect(() =>
      signWebhook({ secrets: TEST_SECRET, payload: 'x', timestamp: TEST_TIMESTAMP, nonce: 'a.b' }),
    ).toThrow(/nonce/);

    expect(() =>
      signWebhook({
        secrets: TEST_SECRET,
        payload: null as unknown as string,
        timestamp: TEST_TIMESTAMP,
        nonce: 'n',
      }),
    ).toThrow(/payload/);
  });
});

describe('migration oracle: what the adapters put on the wire', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function createRes() {
    const res = {
      statusCode: 0,
      body: null as unknown,
      status(code: number) {
        res.statusCode = code;
        return res;
      },
      json(body: unknown) {
        res.body = body;
      },
    };
    return res;
  }

  function createReq(headers: Record<string, string>) {
    return {
      body: firstVector.payload,
      headers: headers as Record<string, string | string[] | undefined>,
      webhookVerified: undefined as boolean | undefined,
    };
  }

  const goodHeaders = () => ({
    'x-webhook-signature': firstVector.signature,
    'x-webhook-timestamp': String(firstVector.timestamp),
    'x-webhook-nonce': firstVector.nonce,
  });

  it('lets a valid request through', async () => {
    const req = createReq(goodHeaders());
    const res = createRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
    expect(res.statusCode).toBe(0);
  });

  it('answers every verification failure with 401 and one body', async () => {
    const req = createReq({ ...goodHeaders(), 'x-webhook-signature': `v2=${'0'.repeat(64)}` });
    const res = createRes();
    const onError = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, vi.fn());

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(onError).toHaveBeenCalledWith(expect.any(WebhookSignatureError));
    expect(req.webhookVerified).toBeUndefined();
  });

  it('answers anything that is not a verification failure with 500', async () => {
    const req = createReq(goodHeaders());
    const res = createRes();

    webhookVerifier({ secrets: TEST_SECRET, tolerance: Number.NaN })(req, res, vi.fn());

    await vi.waitFor(() => expect(res.statusCode).toBe(500));
    expect(res.body).toEqual({ error: 'Internal server error' });
  });
});
