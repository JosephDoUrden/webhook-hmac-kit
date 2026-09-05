import { createHmac, timingSafeEqual } from 'node:crypto';
import { buildCanonicalString, isValidNonce, isValidTimestamp } from './canonical.js';
import { WebhookNonceError, WebhookSignatureError, WebhookTimestampError } from './errors.js';
import { parseSignature } from './signature.js';
import { DEFAULT_TOLERANCE_SECONDS, SIGNATURE_VERSION } from './types.js';
import type { VerifyWebhookOptions, VerifyWebhookResult } from './types.js';

export async function verifyWebhook(options: VerifyWebhookOptions): Promise<VerifyWebhookResult> {
  if (!options.secret) {
    throw new Error('secret must not be empty');
  }

  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;

  if (!Number.isFinite(tolerance) || tolerance < 0) {
    throw new Error('tolerance must be a non-negative finite number');
  }

  // 1. Timestamp check (cheapest — no crypto, no I/O)
  if (!isValidTimestamp(options.timestamp)) {
    throw new WebhookTimestampError(
      'Webhook timestamp must be a non-negative integer',
      'WEBHOOK_TIMESTAMP_INVALID',
    );
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - options.timestamp) > tolerance) {
    throw new WebhookTimestampError();
  }

  // 2. Nonce grammar (still no crypto). A nonce outside the grammar cannot have been signed by a
  //    conforming sender, and letting it through would reopen the delimiter ambiguity.
  if (!isValidNonce(options.nonce)) {
    throw new WebhookNonceError('Webhook nonce is malformed', 'WEBHOOK_NONCE_INVALID');
  }

  // 3. Signature syntax and scheme version, before any HMAC work. Only the current scheme is
  //    accepted; an older or unknown version is refused rather than tried.
  const parsed = parseSignature(options.signature);
  if (!parsed) {
    throw new WebhookSignatureError('Webhook signature is malformed');
  }
  if (parsed.version !== SIGNATURE_VERSION) {
    throw new WebhookSignatureError('Webhook signature version is not supported');
  }

  // 4. Signature check (crypto, but no I/O)
  const canonical = buildCanonicalString(options.timestamp, options.nonce, options.payload);
  const expected = createHmac('sha256', options.secret).update(canonical).digest();

  // Both sides are 32 bytes by construction (SHA-256 digest, 64 hex chars parsed above), so
  // timingSafeEqual cannot throw on length.
  if (!timingSafeEqual(expected, parsed.digest)) {
    throw new WebhookSignatureError();
  }

  // 5. Nonce replay check (may involve network I/O — last)
  if (options.nonceValidator) {
    const isValid = await options.nonceValidator(options.nonce);
    if (!isValid) {
      throw new WebhookNonceError();
    }
  }

  return { valid: true };
}
