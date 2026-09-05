import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  HttpException,
  WEBHOOK_OPTIONS,
  WebhookGuard,
  WebhookModule,
} from '../../src/adapters/nest.js';
import { signWebhook } from '../../src/signer.js';
import { TEST_SECRET, TEST_TIMESTAMP } from '../vectors.js';

const firstVector = {
  payload: '{"event":"payment.completed","amount":4999}',
  nonce: 'nonce_abc123',
};

function signPayload(payload: string, timestamp: number, nonce: string) {
  return signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce }).signature;
}

function createMockContext(overrides: Record<string, unknown> = {}) {
  const request = {
    headers: {} as Record<string, string | string[] | undefined>,
    body: firstVector.payload,
    webhookVerified: undefined as boolean | undefined,
    ...overrides,
  };

  return {
    request,
    switchToHttp() {
      return {
        getRequest() {
          return request;
        },
      };
    },
  };
}

describe('NestJS WebhookGuard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns true for valid webhook', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });

    const guard = new WebhookGuard({ secrets: TEST_SECRET });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(context.request.webhookVerified).toBe(true);
  });

  it('handles Buffer body', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      body: Buffer.from(firstVector.payload),
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });

    const guard = new WebhookGuard({ secrets: TEST_SECRET });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
  });

  it('throws HttpException(400) for missing headers', async () => {
    const context = createMockContext({ headers: {} });
    const guard = new WebhookGuard({ secrets: TEST_SECRET });

    await expect(guard.canActivate(context)).rejects.toThrow(HttpException);

    try {
      await guard.canActivate(context);
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(400);
      expect(err.getResponse()).toEqual({
        error: 'Missing required header: x-webhook-signature',
      });
    }
  });

  it('throws HttpException(401) for invalid signature', async () => {
    const context = createMockContext({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secrets: TEST_SECRET });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(401);
    }
  });

  it('throws HttpException(401) for expired timestamp', async () => {
    vi.setSystemTime((TEST_TIMESTAMP + 600) * 1000);
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secrets: TEST_SECRET });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(401);
      expect(err.getResponse()).toEqual({ error: 'Webhook verification failed' });
    }
  });

  it('throws HttpException(401) for replayed nonce', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({
      secrets: TEST_SECRET,
      nonceValidator: async () => false,
    });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(401);
      expect(err.getResponse()).toEqual({ error: 'Webhook verification failed' });
    }
  });

  it('uses rawBody when the framework provides it alongside a parsed body', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      body: JSON.parse(firstVector.payload),
      rawBody: Buffer.from(firstVector.payload),
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });

    const guard = new WebhookGuard({ secrets: TEST_SECRET });
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('reports a parsed body as a configuration error, through onError', async () => {
    const onError = vi.fn();
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      body: JSON.parse(firstVector.payload),
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });

    const guard = new WebhookGuard({ secrets: TEST_SECRET, onError });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err).toBeInstanceOf(HttpException);
      expect(err.getStatus()).toBe(500);
      expect(err.getResponse()).toEqual({ error: 'Internal server error' });
    }
    expect(String(onError.mock.calls[0]?.[0])).toMatch(/raw body/i);
    expect(context.request.webhookVerified).toBeUndefined();
  });

  it('supports custom header names', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-custom-sig': signature,
        'x-custom-ts': String(TEST_TIMESTAMP),
        'x-custom-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({
      secrets: TEST_SECRET,
      signatureHeader: 'x-custom-sig',
      timestampHeader: 'x-custom-ts',
      nonceHeader: 'x-custom-nonce',
    });

    const result = await guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('calls onError handler on failure', async () => {
    const onError = vi.fn();
    const context = createMockContext({
      headers: {
        'x-webhook-signature': 'a'.repeat(64),
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secrets: TEST_SECRET, onError });

    try {
      await guard.canActivate(context);
    } catch {
      // expected
    }

    expect(onError).toHaveBeenCalled();
  });
});

describe('WebhookModule', () => {
  it('forRoot returns module config with providers and exports', () => {
    const options = { secrets: 'test-secret' };
    const result = WebhookModule.forRoot(options);

    expect(result.module).toBe(WebhookModule);
    expect(result.providers).toHaveLength(2);
    expect(result.providers[0]).toEqual({
      provide: WEBHOOK_OPTIONS,
      useValue: options,
    });
    expect(result.providers[1]).toBe(WebhookGuard);
    expect(result.exports).toContain(WEBHOOK_OPTIONS);
    expect(result.exports).toContain(WebhookGuard);
  });
});

describe('NestJS WebhookGuard header handling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects a header the framework kept as two values', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': [signature, `v2=${'b'.repeat(64)}`],
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secrets: TEST_SECRET });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(400);
      expect(err.getResponse()).toEqual({ error: 'Duplicate header: x-webhook-signature' });
    }
  });
});

describe('NestJS WebhookGuard failure isolation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('still throws the 401 when onError itself throws', async () => {
    const onError = vi.fn(() => {
      throw new Error('the logger blew up');
    });
    const context = createMockContext({
      headers: {
        'x-webhook-signature': `v2=${'a'.repeat(64)}`,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secrets: TEST_SECRET, onError });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err).toBeInstanceOf(HttpException);
      expect(err.getStatus()).toBe(401);
      expect(err.getResponse()).toEqual({ error: 'Webhook verification failed' });
    }
  });
});
