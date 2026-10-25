import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import type { WebhookVariables } from '../../src/adapters/hono.js';
import { standardWebhooksVerifier, webhookVerifier } from '../../src/adapters/hono.js';
import { WebhookNonceError, WebhookSignatureError } from '../../src/errors.js';
import { signWebhook } from '../../src/signer.js';
import { VECTOR_A, WRONG_KEY_SIGNATURE } from '../standard-webhooks-vectors.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

const URL = 'https://example.test/webhook';
const PAYLOAD = '{"event":"payment.completed","amount":4999}';
const NONCE = 'nonce_abc123';

/** Just the parts of a Hono Context the middleware touches. */
function createMockContext(request: Request) {
  const vars = new Map<string, unknown>();
  const c = {
    req: { raw: request },
    vars,
    set: vi.fn((key: string, value: unknown) => {
      vars.set(key, value);
    }),
    json: vi.fn((body: unknown, status?: number) => Response.json(body, { status: status ?? 200 })),
  };
  return c;
}

function swRequest(signature = VECTOR_A.signature): Request {
  return new Request(URL, {
    method: 'POST',
    body: VECTOR_A.payload,
    headers: {
      'webhook-id': VECTOR_A.messageId,
      'webhook-timestamp': String(VECTOR_A.timestamp),
      'webhook-signature': signature,
    },
  });
}

async function v2Request(headers: Record<string, string> = {}): Promise<Request> {
  const { signature } = await signWebhook({
    secrets: TEST_SECRET,
    payload: PAYLOAD,
    timestamp: TEST_TIMESTAMP,
    nonce: NONCE,
  });
  return new Request(URL, {
    method: 'POST',
    body: PAYLOAD,
    headers: {
      'x-webhook-signature': signature,
      'x-webhook-timestamp': String(TEST_TIMESTAMP),
      'x-webhook-nonce': NONCE,
      ...headers,
    },
  });
}

describe('Hono standardWebhooksVerifier', () => {
  const options = { secrets: VECTOR_A.secret, now: VECTOR_A.timestamp };

  it('sets webhookPayload and awaits next on a valid request', async () => {
    const c = createMockContext(swRequest());
    let payloadSeenByNext: unknown;
    const next = vi.fn(async () => {
      payloadSeenByNext = c.vars.get('webhookPayload');
    });

    const returned = await standardWebhooksVerifier(options)(c, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(returned).toBeUndefined();
    expect(c.json).not.toHaveBeenCalled();
    expect(payloadSeenByNext).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(payloadSeenByNext as Uint8Array)).toBe(VECTOR_A.payload);
  });

  it('returns c.json with 401 and does not call next on a bad signature', async () => {
    const onError = vi.fn();
    const c = createMockContext(swRequest(WRONG_KEY_SIGNATURE));
    const next = vi.fn(async () => {});

    const returned = await standardWebhooksVerifier({ ...options, onError })(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(c.set).not.toHaveBeenCalled();
    expect(c.json).toHaveBeenCalledWith({ error: 'Webhook verification failed' }, 401);
    expect(returned).toBeInstanceOf(Response);
    expect(returned?.status).toBe(401);
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookSignatureError);
  });

  it('answers a body that was already read with 500', async () => {
    const request = swRequest();
    await request.text();
    const c = createMockContext(request);
    const next = vi.fn(async () => {});

    await standardWebhooksVerifier(options)(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(c.json).toHaveBeenCalledWith({ error: 'Internal server error' }, 500);
  });

  // A throw from the route itself is Hono's to handle, not a failed verification.
  it('lets an error from next propagate without reporting it', async () => {
    const onError = vi.fn();
    const c = createMockContext(swRequest());
    const boom = new Error('handler broke');

    await expect(
      standardWebhooksVerifier({ ...options, onError })(c, async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    expect(onError).not.toHaveBeenCalled();
    expect(c.json).not.toHaveBeenCalled();
  });
});

describe('Hono webhookVerifier', () => {
  const options = { secrets: TEST_SECRET, now: TEST_TIMESTAMP };

  it('sets webhookPayload and awaits next on a valid request', async () => {
    const c = createMockContext(await v2Request());
    const next = vi.fn(async () => {});

    await webhookVerifier(options)(c, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(c.set).toHaveBeenCalledWith('webhookPayload', expect.any(Uint8Array));
    expect(new TextDecoder().decode(c.vars.get('webhookPayload') as Uint8Array)).toBe(PAYLOAD);
  });

  it('returns c.json with 400 for a missing header', async () => {
    const request = await v2Request();
    request.headers.delete('x-webhook-signature');
    const c = createMockContext(request);
    const next = vi.fn(async () => {});

    await webhookVerifier(options)(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(c.json).toHaveBeenCalledWith(
      { error: 'Missing required header: x-webhook-signature' },
      400,
    );
  });

  it('returns c.json with 401 for a replay and reports it to onError', async () => {
    const onError = vi.fn();
    const c = createMockContext(await v2Request());
    const next = vi.fn(async () => {});

    await webhookVerifier({ ...options, nonceValidator: async () => false, onError })(c, next);

    expect(next).not.toHaveBeenCalled();
    expect(c.json).toHaveBeenCalledWith({ error: 'Webhook verification failed' }, 401);
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookNonceError);
  });

  it('returns c.json with 500 for a configuration error', async () => {
    const onError = vi.fn();
    const c = createMockContext(await v2Request());

    await webhookVerifier({ secrets: '', now: TEST_TIMESTAMP, onError })(c, async () => {});

    expect(c.json).toHaveBeenCalledWith({ error: 'Internal server error' }, 500);
    expect(onError).toHaveBeenCalledTimes(1);
  });
});

describe('WebhookVariables', () => {
  it('types webhookPayload as bytes', () => {
    expectTypeOf<WebhookVariables>().toEqualTypeOf<{ webhookPayload: Uint8Array }>();
  });
});
