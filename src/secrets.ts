import type { WebhookSecret } from './types.js';

/**
 * Accepts a single secret or a list of active secrets and returns the key material as bytes.
 *
 * A list is how rotation works: the sender signs with the first entry, the receiver accepts a
 * signature made with any entry. Keep the outgoing secret first and the retiring one after it
 * while both are live, then drop the old one. Duplicates are collapsed and the list is capped at
 * MAX_SECRETS, which is more than any rotation needs.
 *
 * A string secret is UTF-8 encoded, which is what createHmac would have done with it anyway. A
 * secret that is not UTF-8 text — a decoded base64 key, say — has to arrive as bytes, because
 * UTF-8 encoding maps every unpaired surrogate onto the same three bytes and two different keys
 * would end up as one.
 */
export const MAX_SECRETS = 16;

export function normalizeSecrets(secrets: WebhookSecret | WebhookSecret[]): [Buffer, ...Buffer[]] {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  if (list.length === 0 || list.some((s) => !isUsableSecret(s))) {
    throw new Error('secrets must not be empty');
  }

  // Every entry costs an HMAC on every request, whether or not an earlier one matched, so a
  // repeated secret is paid for and buys nothing. Duplicates collapse and the cap applies to what
  // is left: one secret listed forty times is a mistake, not forty live keys.
  const unique = new Map<string, Buffer>();
  for (const secret of list) {
    const bytes = toKeyBytes(secret);
    const seen = bytes.toString('base64');
    if (!unique.has(seen)) {
      unique.set(seen, bytes);
    }
  }

  if (unique.size > MAX_SECRETS) {
    throw new Error(
      `secrets must not contain more than ${MAX_SECRETS} distinct entries, got ${unique.size}`,
    );
  }

  return [...unique.values()] as [Buffer, ...Buffer[]];
}

function isUsableSecret(secret: WebhookSecret): boolean {
  if (typeof secret === 'string') return secret.length > 0;
  return secret instanceof Uint8Array && secret.length > 0;
}

function toKeyBytes(secret: WebhookSecret): Buffer {
  return typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
}
