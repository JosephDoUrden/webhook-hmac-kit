import { bytesEqual, utf8 } from './bytes.js';
import type { WebhookSecret } from './types.js';

/**
 * Accepts a single secret or a list of active secrets and returns the key material as bytes.
 *
 * A list is how rotation works: the sender signs with the first entry, the receiver accepts a
 * signature made with any entry. Keep the outgoing secret first and the retiring one after it
 * while both are live, then drop the old one. Duplicates are collapsed and the list is capped at
 * MAX_SECRETS, which is more than any rotation needs.
 *
 * A string secret is UTF-8 encoded, which is what any HMAC implementation would have done with it
 * anyway. A secret that is not UTF-8 text — a decoded base64 key, say — has to arrive as bytes,
 * because UTF-8 encoding maps every unpaired surrogate onto the same three bytes and two different
 * keys would end up as one.
 *
 * An empty entry is refused here rather than at the crypto layer. Web Crypto rejects a zero-length
 * key with a spec-mandated DataError, which is a true statement about nothing anybody configured
 * on purpose; naming the mistake is more use than relaying it.
 */
export const MAX_SECRETS = 16;

export function normalizeSecrets(
  secrets: WebhookSecret | WebhookSecret[],
): [Uint8Array, ...Uint8Array[]] {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  // Two different mistakes: no secrets configured at all, and a list with a blank or wrong-typed
  // entry in it. One message for both sent people looking at the wrong thing.
  if (list.length === 0) {
    throw new Error('secrets must not be empty');
  }
  if (list.some((s) => !isUsableSecret(s))) {
    throw new Error('each secret must be a non-empty string or byte array');
  }

  // Every entry costs an HMAC on every request, whether or not an earlier one matched, so a
  // repeated secret is paid for and buys nothing. Duplicates collapse and the cap applies to what
  // is left: one secret listed forty times is a mistake, not forty live keys.
  // Compared as bytes rather than through a string key. Sixteen entries of thirty-odd bytes is
  // 120 comparisons at worst, and it keeps key material out of a second representation that the
  // engine would keep alive for as long as the Map did.
  const unique: Uint8Array[] = [];
  for (const secret of list) {
    const bytes = toKeyBytes(secret);
    if (unique.some((seen) => bytesEqual(seen, bytes))) {
      continue;
    }
    unique.push(bytes);

    // Refused at the entry that breaks the cap rather than after the whole list has been walked.
    // The dedupe is the quadratic part — every new entry is compared against every kept one — so
    // stopping here is what bounds it, and a caller who passed ten thousand secrets does not get
    // that work done for them before being told no. The count is left out of the message because
    // by then it has not been counted: the honest thing to report is the limit.
    if (unique.length > MAX_SECRETS) {
      throw new Error(`secrets must not contain more than ${MAX_SECRETS} distinct entries`);
    }
  }

  return unique as [Uint8Array, ...Uint8Array[]];
}

function isUsableSecret(secret: WebhookSecret): boolean {
  if (typeof secret === 'string') return secret.length > 0;
  return secret instanceof Uint8Array && secret.length > 0;
}

function toKeyBytes(secret: WebhookSecret): Uint8Array {
  // Bytes are copied: the caller keeps its array and may reuse or clear it, and a key that changed
  // under the verifier between two candidates would make the result depend on the timing.
  return typeof secret === 'string' ? utf8(secret) : Uint8Array.from(secret);
}
