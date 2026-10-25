import { describe, expect, it, vi } from 'vitest';
import { verifyStandardWebhooksRequest, verifyWebhookRequest } from '../../src/adapters/web.js';
import {
  WebhookNonceError,
  WebhookSignatureError,
  WebhookTimestampError,
} from '../../src/errors.js';
import { signWebhook } from '../../src/signer.js';
import { VECTOR_A, WRONG_KEY_SIGNATURE } from '../standard-webhooks-vectors.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

const URL = 'https://example.test/webhook';
const PAYLOAD = '{"event":"payment.completed","amount":4999}';
const NONCE = 'nonce_abc123';

function swRequest(
  headers: Record<string, string> = {},
  body: string | Uint8Array = VECTOR_A.payload,
): Request {
  return new Request(URL, {
    method: 'POST',
    body,
    headers: {
      'webhook-id': VECTOR_A.messageId,
      'webhook-timestamp': String(VECTOR_A.timestamp),
      'webhook-signature': VECTOR_A.signature,
      ...headers,
    },
  });
}

const swOptions = { secrets: VECTOR_A.secret, now: VECTOR_A.timestamp };

async function v2Headers(payload: string | Uint8Array = PAYLOAD): Promise<Headers> {
  const { signature } = await signWebhook({
    secrets: TEST_SECRET,
    payload,
    timestamp: TEST_TIMESTAMP,
    nonce: NONCE,
  });
  return new Headers({
    'x-webhook-signature': signature,
    'x-webhook-timestamp': String(TEST_TIMESTAMP),
    'x-webhook-nonce': NONCE,
  });
}

function v2Request(headers: Headers, body: string | Uint8Array = PAYLOAD): Request {
  return new Request(URL, { method: 'POST', body, headers });
}

const v2Options = { secrets: TEST_SECRET, now: TEST_TIMESTAMP };

describe('verifyStandardWebhooksRequest', () => {
  it('accepts a valid request and returns the body bytes', async () => {
    const result = await verifyStandardWebhooksRequest(swRequest(), swOptions);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(result.payload)).toBe(VECTOR_A.payload);
  });

  it('passes now through, so the same request outside the window is a 401', async () => {
    const onError = vi.fn();
    const result = await verifyStandardWebhooksRequest(swRequest(), {
      secrets: VECTOR_A.secret,
      now: VECTOR_A.timestamp + 301,
      onError,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookTimestampError);
  });

  it('answers a bad signature with 401 and a generic JSON body', async () => {
    const onError = vi.fn();
    const result = await verifyStandardWebhooksRequest(
      swRequest({ 'webhook-signature': WRONG_KEY_SIGNATURE }),
      { ...swOptions, onError },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookSignatureError);
    expect(onError).toHaveBeenCalledWith(result.error);
    expect(result.response.status).toBe(401);
    expect(result.response.headers.get('content-type')).toMatch(/^application\/json/);
    expect(await result.response.json()).toEqual({ error: 'Webhook verification failed' });
  });

  it('answers a body that does not match the signature with 401', async () => {
    const result = await verifyStandardWebhooksRequest(
      swRequest({}, Uint8Array.from([0x7b, 0xff, 0x7d])),
      swOptions,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
  });

  // The Quick Start says the same: Standard Webhooks has no 400. A missing header is a request
  // that failed to verify, and the core throws WebhookSignatureError for it.
  it('answers a missing header with 401, not 400', async () => {
    const request = swRequest();
    request.headers.delete('webhook-id');
    const result = await verifyStandardWebhooksRequest(request, swOptions);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookSignatureError);
  });

  // Fetch Headers folds a repeated header into one value joined by ", ". The signature header is a
  // space-separated list, so the fold leaves a trailing comma on every entry but the last; those no
  // longer decode and are skipped, and the last one is weighed as usual. Pinned, not endorsed: the
  // sender controls the whole header either way.
  it('weighs the last entry of a folded signature header and skips the rest', async () => {
    const validLast = swRequest({ 'webhook-signature': WRONG_KEY_SIGNATURE });
    validLast.headers.append('webhook-signature', VECTOR_A.signature);
    expect(validLast.headers.get('webhook-signature')).toBe(
      `${WRONG_KEY_SIGNATURE}, ${VECTOR_A.signature}`,
    );
    expect((await verifyStandardWebhooksRequest(validLast, swOptions)).ok).toBe(true);

    const validFirst = swRequest();
    validFirst.headers.append('webhook-signature', WRONG_KEY_SIGNATURE);
    const result = await verifyStandardWebhooksRequest(validFirst, swOptions);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
  });

  it('answers a configuration error with 500 and reports it', async () => {
    const onError = vi.fn();
    const result = await verifyStandardWebhooksRequest(swRequest(), {
      secrets: '',
      now: VECTOR_A.timestamp,
      onError,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(500);
    expect(result.error).toBeInstanceOf(TypeError);
    expect(onError).toHaveBeenCalledWith(result.error);
    expect(await result.response.json()).toEqual({ error: 'Internal server error' });
  });

  it('refuses a request whose body was already read, naming request.clone()', async () => {
    const request = swRequest();
    await request.text();
    const onError = vi.fn();
    const result = await verifyStandardWebhooksRequest(request, { ...swOptions, onError });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(500);
    expect(result.error.message).toMatch(/request\.clone\(\)/);
    expect(onError).toHaveBeenCalledWith(result.error);
    expect(await result.response.json()).toEqual({ error: 'Internal server error' });
  });

  it('reads the body once, as bytes', async () => {
    const request = swRequest();
    const arrayBuffer = vi.spyOn(request, 'arrayBuffer');
    const text = vi.spyOn(request, 'text');

    expect((await verifyStandardWebhooksRequest(request, swOptions)).ok).toBe(true);
    expect(arrayBuffer).toHaveBeenCalledTimes(1);
    expect(text).not.toHaveBeenCalled();
  });

  // JSON.stringify(error) would put its code and name on the wire and bring the status oracle
  // back, so a result serialised whole must not carry it.
  it('keeps error off a serialised failure result', async () => {
    const result = await verifyStandardWebhooksRequest(
      swRequest({ 'webhook-signature': WRONG_KEY_SIGNATURE }),
      swOptions,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(WebhookSignatureError);
    expect(Object.keys(result)).not.toContain('error');
    expect(JSON.stringify(result)).not.toMatch(/WEBHOOK_|WebhookSignatureError/);
    expect(await Response.json(result).json()).not.toHaveProperty('error');
  });

  it('still answers when onError throws', async () => {
    const result = await verifyStandardWebhooksRequest(
      swRequest({ 'webhook-signature': WRONG_KEY_SIGNATURE }),
      {
        ...swOptions,
        onError: () => {
          throw new Error('logger down');
        },
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
  });
});

describe('verifyWebhookRequest', () => {
  it('accepts a valid request and returns the body bytes', async () => {
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), v2Options);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(new TextDecoder().decode(result.payload)).toBe(PAYLOAD);
  });

  it('verifies a byte body that is not valid UTF-8', async () => {
    const bytes = Uint8Array.from([0x7b, 0xff, 0x7d]);
    const result = await verifyWebhookRequest(v2Request(await v2Headers(bytes), bytes), v2Options);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.payload).toEqual(bytes);
  });

  it('passes the nonce to the validator and accepts when it says fresh', async () => {
    const nonceValidator = vi.fn(async () => true);
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), {
      ...v2Options,
      nonceValidator,
    });

    expect(result.ok).toBe(true);
    expect(nonceValidator).toHaveBeenCalledWith(NONCE);
  });

  it('answers a replayed nonce with 401, not 409, with the reason only in onError', async () => {
    const onError = vi.fn();
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), {
      ...v2Options,
      nonceValidator: async () => false,
      onError,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookNonceError);
    expect(onError).toHaveBeenCalledWith(result.error);
    expect(await result.response.json()).toEqual({ error: 'Webhook verification failed' });
  });

  it('passes now through, so the same request outside the window is a 401', async () => {
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), {
      secrets: TEST_SECRET,
      now: TEST_TIMESTAMP + 301,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookTimestampError);
  });

  it('answers a missing header with 400 and names it', async () => {
    const headers = await v2Headers();
    headers.delete('x-webhook-nonce');
    const onError = vi.fn();
    const result = await verifyWebhookRequest(v2Request(headers), { ...v2Options, onError });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(400);
    expect(result.error.message).toBe('Missing required header: x-webhook-nonce');
    expect(result.response.status).toBe(400);
    expect(await result.response.json()).toEqual({
      error: 'Missing required header: x-webhook-nonce',
    });
    // Same as the Express, Fastify and Nest adapters: a malformed request is not a verification
    // failure and does not go to onError.
    expect(onError).not.toHaveBeenCalled();
  });

  it('reads configured header names case-insensitively', async () => {
    const signed = await v2Headers();
    const headers = new Headers({
      'x-custom-signature': signed.get('x-webhook-signature') ?? '',
      'x-webhook-timestamp': String(TEST_TIMESTAMP),
      'x-webhook-nonce': NONCE,
    });
    const result = await verifyWebhookRequest(v2Request(headers), {
      ...v2Options,
      signatureHeader: 'X-Custom-Signature',
    });

    expect(result.ok).toBe(true);
  });

  // Headers folds a repeated header into "a, b", which is a string and not an array, so it gets
  // past the duplicate-header 400 and fails the grammar instead. Pinned: it fails closed as 401.
  it('fails a folded duplicate timestamp closed with 401', async () => {
    const headers = await v2Headers();
    headers.append('x-webhook-timestamp', String(TEST_TIMESTAMP));
    expect(headers.get('x-webhook-timestamp')).toBe(`${TEST_TIMESTAMP}, ${TEST_TIMESTAMP}`);
    const result = await verifyWebhookRequest(v2Request(headers), v2Options);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookTimestampError);
  });

  it('fails a folded duplicate nonce closed with 401', async () => {
    const headers = await v2Headers();
    headers.append('x-webhook-nonce', NONCE);
    const result = await verifyWebhookRequest(v2Request(headers), v2Options);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookNonceError);
  });

  it('answers a configuration error with 500 and reports it', async () => {
    const onError = vi.fn();
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), {
      secrets: '',
      now: TEST_TIMESTAMP,
      onError,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(500);
    expect(onError).toHaveBeenCalledWith(result.error);
    expect(await result.response.json()).toEqual({ error: 'Internal server error' });
  });

  // A nonce store that is down answers like a replay, so it is no status oracle either.
  it('answers a nonce validator that throws with 401, carrying the cause', async () => {
    const onError = vi.fn();
    const result = await verifyWebhookRequest(v2Request(await v2Headers()), {
      ...v2Options,
      nonceValidator: async () => {
        throw 'store unreachable';
      },
      onError,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(401);
    expect(result.error).toBeInstanceOf(WebhookNonceError);
    expect(result.error.cause).toBe('store unreachable');
    expect(onError).toHaveBeenCalledWith(result.error);
  });

  it('refuses a request whose body was already read, naming request.clone()', async () => {
    const request = v2Request(await v2Headers());
    await request.arrayBuffer();
    const onError = vi.fn();
    const result = await verifyWebhookRequest(request, { ...v2Options, onError });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(500);
    expect(result.error.message).toMatch(/request\.clone\(\)/);
    expect(onError).toHaveBeenCalledWith(result.error);
  });

  it('verifies a clone taken before the body was read', async () => {
    const request = v2Request(await v2Headers());
    const copy = request.clone();
    await request.text();

    expect((await verifyWebhookRequest(copy, v2Options)).ok).toBe(true);
  });

  it('reads the body once, as bytes', async () => {
    const request = v2Request(await v2Headers());
    const arrayBuffer = vi.spyOn(request, 'arrayBuffer');

    expect((await verifyWebhookRequest(request, v2Options)).ok).toBe(true);
    expect(arrayBuffer).toHaveBeenCalledTimes(1);
  });
});
