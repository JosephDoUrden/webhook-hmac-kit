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
  return signWebhook({ secret: TEST_SECRET, payload, timestamp, nonce }).signature;
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

    const guard = new WebhookGuard({ secret: TEST_SECRET });
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

    const guard = new WebhookGuard({ secret: TEST_SECRET });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
  });

  it('throws HttpException(400) for missing headers', async () => {
    const context = createMockContext({ headers: {} });
    const guard = new WebhookGuard({ secret: TEST_SECRET });

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
    const guard = new WebhookGuard({ secret: TEST_SECRET });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(401);
    }
  });

  it('throws HttpException(400) for expired timestamp', async () => {
    vi.setSystemTime((TEST_TIMESTAMP + 600) * 1000);
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({ secret: TEST_SECRET });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(400);
    }
  });

  it('throws HttpException(409) for replayed nonce', async () => {
    const signature = signPayload(firstVector.payload, TEST_TIMESTAMP, firstVector.nonce);
    const context = createMockContext({
      headers: {
        'x-webhook-signature': signature,
        'x-webhook-timestamp': String(TEST_TIMESTAMP),
        'x-webhook-nonce': firstVector.nonce,
      },
    });
    const guard = new WebhookGuard({
      secret: TEST_SECRET,
      nonceValidator: async () => false,
    });

    try {
      await guard.canActivate(context);
      expect.fail('Should have thrown');
    } catch (e) {
      const err = e as HttpException;
      expect(err.getStatus()).toBe(409);
    }
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
      secret: TEST_SECRET,
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
    const guard = new WebhookGuard({ secret: TEST_SECRET, onError });

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
    const options = { secret: 'test-secret' };
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
