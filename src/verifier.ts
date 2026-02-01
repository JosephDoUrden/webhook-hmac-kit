import { createHmac, timingSafeEqual } from 'node:crypto';
import { buildCanonicalString } from './canonical.js';
import { WebhookNonceError, WebhookSignatureError, WebhookTimestampError } from './errors.js';
import { DEFAULT_TOLERANCE_SECONDS, DEFAULT_VERSION } from './types.js';
import type { VerifyWebhookOptions, VerifyWebhookResult } from './types.js';

export async function verifyWebhook(options: VerifyWebhookOptions): Promise<VerifyWebhookResult> {
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const version = DEFAULT_VERSION;

  // 1. Timestamp check (cheapest — no crypto, no I/O)
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - options.timestamp) > tolerance) {
    throw new WebhookTimestampError();
  }

  // 2. Signature check (crypto, but no I/O)
  const canonical = buildCanonicalString(
    version,
    options.timestamp,
    options.nonce,
    options.payload,
  );
  const expected = createHmac('sha256', options.secret).update(canonical).digest();
  const received = Buffer.from(options.signature, 'hex');

  // Length guard: prevents RangeError from timingSafeEqual on mismatched lengths.
  // Also catches malformed (non-hex / wrong-length) signatures.
  if (expected.length !== received.length) {
    throw new WebhookSignatureError();
  }

  if (!timingSafeEqual(expected, received)) {
    throw new WebhookSignatureError();
  }

  // 3. Nonce check (may involve network I/O — last)
  if (options.nonceValidator) {
    const isValid = await options.nonceValidator(options.nonce);
    if (!isValid) {
      throw new WebhookNonceError();
    }
  }

  return { valid: true };
}
