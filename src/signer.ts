import { createHmac } from 'node:crypto';
import { buildCanonicalString } from './canonical.js';
import { formatSignature } from './signature.js';
import { SIGNATURE_VERSION } from './types.js';
import type { SignWebhookOptions, SignWebhookResult } from './types.js';

export function signWebhook(options: SignWebhookOptions): SignWebhookResult {
  if (!options.secret) {
    throw new Error('secret must not be empty');
  }

  const canonical = buildCanonicalString(options.timestamp, options.nonce, options.payload);
  const digest = createHmac('sha256', options.secret).update(canonical).digest();
  return { signature: formatSignature(SIGNATURE_VERSION, digest) };
}
