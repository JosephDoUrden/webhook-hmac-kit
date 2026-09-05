import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebhookNonceError, WebhookSignatureError, WebhookTimestampError } from '../src/errors.js';
import { signWebhook } from '../src/signer.js';
import { verifyWebhook } from '../src/verifier.js';
import { TEST_SECRET, TEST_TIMESTAMP, vectors } from './vectors.js';

// Extract first vector at module level — vectors is a static array with known contents.
const firstVector = vectors[0] as (typeof vectors)[number];

describe('verifyWebhook', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(TEST_TIMESTAMP * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('happy path', () => {
    it('accepts a valid signature', async () => {
      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      });
      expect(result).toEqual({ valid: true });
    });

    for (const vector of vectors) {
      it(`verifies vector: ${vector.name}`, async () => {
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

  describe('timestamp validation', () => {
    it('rejects expired timestamp (too old)', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 360) * 1000);

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('rejects future timestamp (too far ahead)', async () => {
      vi.setSystemTime((TEST_TIMESTAMP - 360) * 1000);

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('accepts timestamp at exact tolerance boundary', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 300) * 1000);

      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      });
      expect(result).toEqual({ valid: true });
    });

    it('rejects timestamp one second past tolerance', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 301) * 1000);

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('respects custom tolerance', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 10) * 1000);

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          tolerance: 5,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('accepts within custom tolerance', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 10) * 1000);

      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        tolerance: 60,
      });
      expect(result).toEqual({ valid: true });
    });
  });

  describe('signature validation', () => {
    it('rejects wrong signature', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: 'a'.repeat(64),
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects tampered payload', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: `${firstVector.payload} tampered`,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects wrong secret', async () => {
      await expect(
        verifyWebhook({
          secrets: 'wrong_secret',
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects malformed signature (wrong length)', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: 'tooshort',
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects malformed signature (non-hex characters)', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: 'zz'.repeat(32),
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects a bare hex digest with no scheme version', async () => {
      const hex = firstVector.signature.slice('v2='.length);
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: hex,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects a signature with an unsupported scheme version', async () => {
      const hex = firstVector.signature.slice('v2='.length);
      for (const version of ['v1', 'v3', 'v22', 'V2']) {
        await expect(
          verifyWebhook({
            secrets: TEST_SECRET,
            payload: firstVector.payload,
            signature: `${version}=${hex}`,
            timestamp: firstVector.timestamp,
            nonce: firstVector.nonce,
          }),
        ).rejects.toThrow(WebhookSignatureError);
      }
    });

    it('rejects a valid signature with trailing garbage', async () => {
      for (const suffix of ['zz', ' ', '!!!!', 'ZZZZZZZZ', '0']) {
        await expect(
          verifyWebhook({
            secrets: TEST_SECRET,
            payload: firstVector.payload,
            signature: firstVector.signature + suffix,
            timestamp: firstVector.timestamp,
            nonce: firstVector.nonce,
          }),
        ).rejects.toThrow(WebhookSignatureError);
      }
    });

    it('rejects upper-case hex', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature.toUpperCase().replace('V2', 'v2'),
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects a folded duplicate header value ("sigA, sigB")', async () => {
      const folded = `${firstVector.signature}, v2=${'f'.repeat(64)}`;
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: folded,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects surrounding whitespace', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: ` ${firstVector.signature}`,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });

    it('rejects empty signature', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: '',
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });
  });

  describe('nonce validation', () => {
    it('rejects replayed nonce', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          nonceValidator: async () => false,
        }),
      ).rejects.toThrow(WebhookNonceError);
    });

    it('accepts valid nonce', async () => {
      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        nonceValidator: async () => true,
      });
      expect(result).toEqual({ valid: true });
    });

    it('passes without nonce validator', async () => {
      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
      });
      expect(result).toEqual({ valid: true });
    });

    it('passes nonce value to validator', async () => {
      const validator = vi.fn().mockResolvedValue(true);

      await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        nonceValidator: validator,
      });

      expect(validator).toHaveBeenCalledWith(firstVector.nonce);
    });

    it('propagates nonceValidator errors', async () => {
      const redisError = new Error('Redis connection failed');

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          nonceValidator: async () => {
            throw redisError;
          },
        }),
      ).rejects.toThrow('Redis connection failed');
    });
  });

  describe('input validation', () => {
    it('rejects empty secret', async () => {
      await expect(
        verifyWebhook({
          secrets: '',
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow('secrets must not be empty');
    });

    it('rejects NaN timestamp', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: Number.NaN,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('rejects a fractional timestamp even when it is inside the window', async () => {
      const timestamp = TEST_TIMESTAMP + 0.5;
      const { signature } = signWebhook({
        secrets: TEST_SECRET,
        payload: 'x',
        timestamp: TEST_TIMESTAMP,
        nonce: 'n',
      });

      await expect(
        verifyWebhook({ secrets: TEST_SECRET, payload: 'x', signature, timestamp, nonce: 'n' }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('rejects a negative timestamp', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: -1,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('rejects a malformed nonce before touching the signature', async () => {
      for (const nonce of ['', 'a.b', 'a:b', 'x'.repeat(65)]) {
        await expect(
          verifyWebhook({
            secrets: TEST_SECRET,
            payload: firstVector.payload,
            signature: 'not-a-signature',
            timestamp: firstVector.timestamp,
            nonce,
          }),
        ).rejects.toThrow(WebhookNonceError);
      }
    });

    it('rejects Infinity timestamp', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: Number.POSITIVE_INFINITY,
          nonce: firstVector.nonce,
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('rejects NaN tolerance', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          tolerance: Number.NaN,
        }),
      ).rejects.toThrow('tolerance must be a non-negative finite number');
    });

    it('rejects Infinity tolerance', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          tolerance: Number.POSITIVE_INFINITY,
        }),
      ).rejects.toThrow('tolerance must be a non-negative finite number');
    });

    it('rejects negative tolerance', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: firstVector.payload,
          signature: firstVector.signature,
          timestamp: firstVector.timestamp,
          nonce: firstVector.nonce,
          tolerance: -1,
        }),
      ).rejects.toThrow('tolerance must be a non-negative finite number');
    });

    it('accepts tolerance of 0 (exact second match only)', async () => {
      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload: firstVector.payload,
        signature: firstVector.signature,
        timestamp: firstVector.timestamp,
        nonce: firstVector.nonce,
        tolerance: 0,
      });
      expect(result).toEqual({ valid: true });
    });
  });

  describe('check ordering', () => {
    it('checks timestamp before signature', async () => {
      vi.setSystemTime((TEST_TIMESTAMP + 600) * 1000);

      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: 'test',
          signature: 'invalid',
          timestamp: TEST_TIMESTAMP,
          nonce: 'n',
        }),
      ).rejects.toThrow(WebhookTimestampError);
    });

    it('checks signature before nonce', async () => {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: 'test',
          signature: 'a'.repeat(64),
          timestamp: TEST_TIMESTAMP,
          nonce: 'n',
          nonceValidator: async () => false,
        }),
      ).rejects.toThrow(WebhookSignatureError);
    });
  });

  describe('round-trip', () => {
    it('sign then verify succeeds', async () => {
      const payload = '{"test": true}';
      const timestamp = TEST_TIMESTAMP;
      const nonce = 'round-trip-nonce';

      const { signature } = signWebhook({
        secrets: TEST_SECRET,
        payload,
        timestamp,
        nonce,
      });

      const result = await verifyWebhook({
        secrets: TEST_SECRET,
        payload,
        signature,
        timestamp,
        nonce,
      });

      expect(result).toEqual({ valid: true });
    });
  });
});
