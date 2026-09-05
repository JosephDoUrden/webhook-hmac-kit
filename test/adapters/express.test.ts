import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webhookVerifier } from '../../src/adapters/express.js';
import { WebhookNonceError, WebhookTimestampError } from '../../src/errors.js';
import { signWebhook } from '../../src/signer.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

const firstVector = {
  payload: '{"event":"payment.completed","amount":4999}',
  nonce: 'nonce_abc123',
};

function createMockReq(overrides: Record<string, unknown> = {}) {
  return {
    body: Buffer.from(firstVector.payload),
    headers: {} as Record<string, string | string[] | undefined>,
    webhookVerified: undefined as boolean | undefined,
    ...overrides,
  };
}

function createMockRes() {
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

function signPayload(payload: string, timestamp: number, nonce: string) {
  return signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce }).signature;
}

describe('Express webhookVerifier middleware', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('calls next() on valid webhook', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    const middleware = webhookVerifier({ secrets: TEST_SECRET });
    middleware(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('handles string body', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      body: firstVector.payload,
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    const middleware = webhookVerifier({ secrets: TEST_SECRET });
    middleware(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('returns 400 for missing signature header', () => {
    const req = createMockReq({
      headers: {
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Missing required header: x-webhook-signature' });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 400 for missing timestamp header', () => {
    const req = createMockReq({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Missing required header: x-webhook-timestamp' });
  });

  it('returns 400 for missing nonce header', () => {
    const req = createMockReq({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Missing required header: x-webhook-nonce' });
  });

  it('returns 401 for invalid signature', async () => {
    const req = createMockReq({
      headers: {
        'x-webhook-signature': `v2=${'a'.repeat(64)}`,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 for expired timestamp, with the detail only in onError', async () => {
    vi.setSystemTime((TEST_TIMESTAMP + 600) * 1000);
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();
    const onError = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookTimestampError);
  });

  it('returns 401 for a non-integer timestamp header', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': `${TEST_TIMESTAMP}.5`,
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();
    const onError = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookTimestampError);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 for replayed nonce, with the detail only in onError', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    const onError = vi.fn();

    webhookVerifier({
      secrets: TEST_SECRET,
      nonceValidator: async () => false,
      onError,
    })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookNonceError);
  });

  it('accepts a signature made with a retiring secret', async () => {
    const signature = signWebhook({
      secrets: 'whsec_old',
      payload: firstVector.payload,
      timestamp: TEST_TIMESTAMP,
      nonce: firstVector.nonce,
    }).signature;
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: [TEST_SECRET, 'whsec_old'] })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('reports a parsed body as a configuration error, through onError', () => {
    const onError = vi.fn();
    const req = createMockReq({
      body: JSON.parse(firstVector.payload),
      headers: {
        'x-webhook-signature': `v2=${'a'.repeat(64)}`,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: 'Internal server error' });
    expect(String(onError.mock.calls[0]?.[0])).toMatch(/raw body/i);
    expect(next).not.toHaveBeenCalled();
  });

  it('supports custom header names', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-custom-sig': signature,
        'x-custom-ts': String(TEST_TIMESTAMP),
        'x-custom-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({
      secrets: TEST_SECRET,
      signatureHeader: 'x-custom-sig',
      timestampHeader: 'x-custom-ts',
      nonceHeader: 'x-custom-nonce',
    })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('calls onError handler on verification failure', async () => {
    const onError = vi.fn();
    const req = createMockReq({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(onError).toHaveBeenCalled());
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(Error);
  });
});

// express.raw() hands over a Buffer. Decoding it to a string before signing would collapse every
// byte sequence that is not valid UTF-8 onto the same replacement characters, so two different
// bodies would share one signature.
describe('Express webhookVerifier with byte bodies', () => {
  const nonce = 'byte_nonce';

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function headersFor(body: Buffer) {
    return {
      'x-webhook-signature': signWebhook({
        secrets: TEST_SECRET,
        payload: body,
        timestamp: TEST_TIMESTAMP,
        nonce,
      }).signature,
      'x-webhook-timestamp': String(TEST_TIMESTAMP),
      'x-webhook-nonce': nonce,
    };
  }

  it('verifies a body that is not valid UTF-8', async () => {
    const body = Buffer.from([0x7b, 0xff, 0x7d]);
    const req = createMockReq({ body, headers: headersFor(body) });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('rejects a body that differs from the signed one only outside valid UTF-8', async () => {
    const req = createMockReq({
      body: Buffer.from([0x7b, 0xfe, 0x7d]),
      headers: headersFor(Buffer.from([0x7b, 0xff, 0x7d])),
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(next).not.toHaveBeenCalled();
  });
});

describe('Express webhookVerifier header handling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects a timestamp header with leading zeros', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': `000${TEST_TIMESTAMP}`,
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();
    const onError = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookTimestampError);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects a header the framework kept as two values', () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': [signature, `v2=${'b'.repeat(64)}`],
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Duplicate header: x-webhook-signature' });
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts a header the framework kept as a single-entry array', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': [signature],
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secrets: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
    expect(req.webhookVerified).toBe(true);
  });

  it('answers 401 when the nonce validator throws, with the cause in onError', async () => {
    const storeError = new Error('Redis connection failed');
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const req = createMockReq({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();
    const onError = vi.fn();

    webhookVerifier({
      secrets: TEST_SECRET,
      nonceValidator: async () => {
        throw storeError;
      },
      onError,
    })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookNonceError);
    expect(onError.mock.calls[0]?.[0]).toHaveProperty('cause', storeError);
    expect(next).not.toHaveBeenCalled();
  });
});

// Real timers here: an unhandled rejection is only reported on a later tick, and there is no way
// to wait for one that a fake clock has swallowed.
describe('Express webhookVerifier failure isolation', () => {
  const timestamp = Math.floor(Date.now() / 1000);

  function validHeaders() {
    return {
      'x-webhook-signature': signPayload(firstVector.payload, timestamp, firstVector.nonce),
      'x-webhook-timestamp': String(timestamp),
      'x-webhook-nonce': firstVector.nonce,
    };
  }

  it('does not treat a throw from the downstream handler as a verification failure', async () => {
    const downstreamError = new Error('the route handler blew up');
    const req = createMockReq({ headers: validHeaders() });
    const res = createMockRes();
    const onError = vi.fn();
    let calls = 0;
    const next = vi.fn(() => {
      calls += 1;
      if (calls === 1) throw downstreamError;
    });

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(next).toHaveBeenCalledTimes(2));
    expect(next.mock.calls[1]?.[0]).toBe(downstreamError);
    expect(onError).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(0);
    expect(res.body).toBeNull();
  });

  it('still answers when onError itself throws', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);

    const req = createMockReq({
      headers: {
        'x-webhook-signature': `v2=${'a'.repeat(64)}`,
        'x-webhook-timestamp': String(timestamp),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();
    const onError = vi.fn(() => {
      throw new Error('the logger blew up');
    });

    webhookVerifier({ secrets: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({ error: 'Webhook verification failed' });
    expect(next).not.toHaveBeenCalled();

    await new Promise((resolve) => setTimeout(resolve, 20));
    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
  });
});
