import { createHmac } from 'node:crypto';
import { buildCanonicalString } from './canonical.js';
import type { SignWebhookOptions, SignWebhookResult } from './types.js';

export function signWebhook(options: SignWebhookOptions): SignWebhookResult {
  if (!options.secret) {
    throw new Error('secret must not be empty');
  }

  const canonical = buildCanonicalString(options.timestamp, options.nonce, options.payload);
  const signature = createHmac('sha256', options.secret).update(canonical).digest('hex');
  return { signature };
}
