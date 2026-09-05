import type { WebhookSecret } from './types.js';

/**
 * Accepts a single secret or a list of active secrets and returns the key material as bytes.
 *
 * A list is how rotation works: the sender signs with the first entry, the receiver accepts a
 * signature made with any entry. Keep the outgoing secret first and the retiring one after it
 * while both are live, then drop the old one.
 *
 * A string secret is UTF-8 encoded, which is what createHmac would have done with it anyway. A
 * secret that is not UTF-8 text — a decoded base64 key, say — has to arrive as bytes, because
 * UTF-8 encoding maps every unpaired surrogate onto the same three bytes and two different keys
 * would end up as one.
 */
export function normalizeSecrets(secrets: WebhookSecret | WebhookSecret[]): [Buffer, ...Buffer[]] {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  if (list.length === 0 || list.some((s) => !isUsableSecret(s))) {
    throw new Error('secrets must not be empty');
  }
  return list.map(toKeyBytes) as [Buffer, ...Buffer[]];
}

function isUsableSecret(secret: WebhookSecret): boolean {
  if (typeof secret === 'string') return secret.length > 0;
  return secret instanceof Uint8Array && secret.length > 0;
}

function toKeyBytes(secret: WebhookSecret): Buffer {
  return typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
}
