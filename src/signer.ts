import { buildCanonicalBytes } from './canonical.js';
import { hmacSha256 } from './crypto.js';
import { normalizeSecrets } from './secrets.js';
import { formatSignature } from './signature.js';
import type { SignWebhookOptions, SignWebhookResult } from './types.js';

/**
 * Signs a webhook. Returns a promise, because Web Crypto has no synchronous HMAC anywhere and
 * never will — every operation in the IDL returns one.
 *
 * Deliberately not an `async function`. An async function cannot throw synchronously, so marking
 * this one would turn every argument mistake — an empty secret list, a nonce outside the grammar,
 * a payload that is not bytes or text — into a rejected promise. A caller that wrote
 * `try { signWebhook(...) } catch {}` around a misconfiguration would stop catching it and get an
 * unhandled rejection instead. Validating eagerly and returning the promise keeps configuration
 * errors where the caller put the call, and only the HMAC itself asynchronous.
 */
export function signWebhook(options: SignWebhookOptions): Promise<SignWebhookResult> {
  const [secret] = normalizeSecrets(options.secrets);
  const canonical = buildCanonicalBytes(options.timestamp, options.nonce, options.payload);

  return hmacSha256(secret, canonical).then((digest) => ({ signature: formatSignature(digest) }));
}
