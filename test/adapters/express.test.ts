import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webhookVerifier } from '../../src/adapters/express.js';
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
  return signWebhook({ secret: TEST_SECRET, payload, timestamp, nonce }).signature;
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

    const middleware = webhookVerifier({ secret: TEST_SECRET });
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

    const middleware = webhookVerifier({ secret: TEST_SECRET });
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

    webhookVerifier({ secret: TEST_SECRET })(req, res, next);

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

    webhookVerifier({ secret: TEST_SECRET })(req, res, next);

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

    webhookVerifier({ secret: TEST_SECRET })(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ error: 'Missing required header: x-webhook-nonce' });
  });

  it('returns 401 for invalid signature', async () => {
    const req = createMockReq({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const res = createMockRes();
    const next = vi.fn();

    webhookVerifier({ secret: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(401));
    expect(res.body).toEqual({
      error: 'Webhook signature is invalid',
      code: 'WEBHOOK_SIGNATURE_INVALID',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 400 for expired timestamp', async () => {
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

    webhookVerifier({ secret: TEST_SECRET })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(400));
    expect(res.body).toEqual({
      error: 'Webhook timestamp has expired',
      code: 'WEBHOOK_TIMESTAMP_EXPIRED',
    });
  });

  it('returns 409 for replayed nonce', async () => {
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

    webhookVerifier({
      secret: TEST_SECRET,
      nonceValidator: async () => false,
    })(req, res, next);

    await vi.waitFor(() => expect(res.statusCode).toBe(409));
    expect(res.body).toEqual({
      error: 'Webhook nonce has been replayed',
      code: 'WEBHOOK_NONCE_REPLAYED',
    });
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
      secret: TEST_SECRET,
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

    webhookVerifier({ secret: TEST_SECRET, onError })(req, res, next);

    await vi.waitFor(() => expect(onError).toHaveBeenCalled());
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(Error);
  });
});
