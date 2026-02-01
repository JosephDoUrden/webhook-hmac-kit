import { createHmac } from 'node:crypto';
import { buildCanonicalString } from './canonical.js';
import { DEFAULT_VERSION } from './types.js';
import type { SignWebhookOptions, SignWebhookResult } from './types.js';

export function signWebhook(options: SignWebhookOptions): SignWebhookResult {
  const version = options.version ?? DEFAULT_VERSION;
  const canonical = buildCanonicalString(
    version,
    options.timestamp,
    options.nonce,
    options.payload,
  );
  const signature = createHmac('sha256', options.secret).update(canonical).digest('hex');
  return { signature };
}
