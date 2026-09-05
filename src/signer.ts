import { createHmac } from 'node:crypto';
import { buildCanonicalBytes } from './canonical.js';
import { normalizeSecrets } from './secrets.js';
import { formatSignature } from './signature.js';
import { SIGNATURE_VERSION } from './types.js';
import type { SignWebhookOptions, SignWebhookResult } from './types.js';

export function signWebhook(options: SignWebhookOptions): SignWebhookResult {
  const [secret] = normalizeSecrets(options.secrets);

  const canonical = buildCanonicalBytes(options.timestamp, options.nonce, options.payload);
  const digest = createHmac('sha256', secret).update(canonical).digest();
  return { signature: formatSignature(SIGNATURE_VERSION, digest) };
}
