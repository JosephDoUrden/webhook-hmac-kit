import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { webhookPlugin } from '../../src/adapters/fastify.js';
import { signWebhook } from '../../src/signer.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

const firstVector = {
  payload: '{"event":"payment.completed","amount":4999}',
  nonce: 'nonce_abc123',
};

function signPayload(payload: string, timestamp: number, nonce: string) {
  return signWebhook({ secret: TEST_SECRET, payload, timestamp, nonce }).signature;
}

function createMockRequest(overrides: Record<string, unknown> = {}) {
  return {
    headers: {} as Record<string, string | string[] | undefined>,
    body: firstVector.payload,
    rawBody: undefined as Buffer | string | undefined,
    webhookVerified: false,
    ...overrides,
  };
}

function createMockReply() {
  const reply = {
    statusCode: 0,
    payload: null as unknown,
    code(status: number) {
      reply.statusCode = status;
      return reply;
    },
    send(body: unknown) {
      reply.payload = body;
      return reply;
    },
  };
  return reply;
}

function createMockFastify() {
  const decorations: Record<string, unknown> = {};
  const requestDecorations: Record<string, unknown> = {};
  return {
    decorations,
    requestDecorations,
    decorate(name: string, value: unknown) {
      decorations[name] = value;
    },
    decorateRequest(name: string, value: unknown) {
      requestDecorations[name] = value;
    },
  };
}

describe('Fastify webhookPlugin', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('registers verifyWebhook decorator', () => {
    const fastify = createMockFastify();
    const done = vi.fn();

    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    expect(fastify.decorations.verifyWebhook).toBeTypeOf('function');
    expect(fastify.requestDecorations.webhookVerified).toBe(false);
    expect(done).toHaveBeenCalled();
  });

  it('verifies valid webhook', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const request = createMockRequest({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(request.webhookVerified).toBe(true);
    expect(reply.statusCode).toBe(0);
  });

  it('uses rawBody when available', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const request = createMockRequest({
      rawBody: Buffer.from(firstVector.payload),
      body: JSON.parse(firstVector.payload),
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(request.webhookVerified).toBe(true);
  });

  it('returns 400 for missing headers', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    const request = createMockRequest({ headers: {} });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(reply.statusCode).toBe(400);
    expect(reply.payload).toEqual({ error: 'Missing required header: x-webhook-signature' });
  });

  it('returns 401 for invalid signature', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    const request = createMockRequest({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(reply.statusCode).toBe(401);
  });

  it('returns 400 for expired timestamp', async () => {
    vi.setSystemTime((TEST_TIMESTAMP + 600) * 1000);
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET }, done);

    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const request = createMockRequest({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(reply.statusCode).toBe(400);
  });

  it('returns 409 for replayed nonce', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET, nonceValidator: async () => false }, done);

    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const request = createMockRequest({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(reply.statusCode).toBe(409);
  });

  it('supports custom header names', async () => {
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(
      fastify,
      {
        secret: TEST_SECRET,
        signatureHeader: 'x-sig',
        timestampHeader: 'x-ts',
        nonceHeader: 'x-nc',
      },
      done,
    );

    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const request = createMockRequest({
      headers: {
        'x-sig': signature,
        'x-ts': String(TEST_TIMESTAMP),
        'x-nc': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(request.webhookVerified).toBe(true);
  });

  it('calls onError handler on failure', async () => {
    const onError = vi.fn();
    const fastify = createMockFastify();
    const done = vi.fn();
    webhookPlugin(fastify, { secret: TEST_SECRET, onError }, done);

    const request = createMockRequest({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const reply = createMockReply();

    const verifyHook = fastify.decorations.verifyWebhook as (
      req: typeof request,
      rep: typeof reply,
    ) => Promise<void>;
    await verifyHook(request, reply);

    expect(onError).toHaveBeenCalled();
  });
});
