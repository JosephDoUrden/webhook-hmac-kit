import { SIGNATURE_VERSION } from './types.js';
import type { WebhookPayload } from './types.js';

/**
 * Grammar for the nonce field. Dot-free by design: the dot is the canonical-string delimiter, so a
 * nonce that could contain one would make the encoding ambiguous.
 */
export const NONCE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** Unix seconds as a non-negative safe integer. Floats, negatives, NaN and >= 2^53 are rejected. */
export function isValidTimestamp(timestamp: number): boolean {
  return Number.isSafeInteger(timestamp) && timestamp >= 0;
}

export function isValidNonce(nonce: string): boolean {
  return typeof nonce === 'string' && NONCE_PATTERN.test(nonce);
}

/**
 * Everything up to and including the third dot: `v2.{timestamp}.{nonce}.`
 *
 * Throws on a malformed timestamp or nonce. Callers that need typed errors (the verifier) check
 * the fields first; this is the last line of defence.
 */
function buildCanonicalPrefix(timestamp: number, nonce: string): string {
  if (!isValidTimestamp(timestamp)) {
    throw new TypeError('timestamp must be a non-negative safe integer (unix seconds)');
  }
  if (!isValidNonce(nonce)) {
    throw new TypeError('nonce must match ^[A-Za-z0-9_-]{1,64}$');
  }
  return `${SIGNATURE_VERSION}.${timestamp}.${nonce}.`;
}

/**
 * Builds the string form of the canonical value:
 *
 *   v2.{timestamp}.{nonce}.{payload}
 *
 * The encoding is injective. The timestamp is a decimal integer and the nonce cannot contain '.',
 * so the first three fields are delimited without ambiguity and the payload is everything after the
 * third dot, dots included. A decoder can always recover the exact (timestamp, nonce, payload)
 * triple, which is what lets the nonce serve as a replay-cache key.
 *
 * This is the readable form, for test vectors and for anything that needs to show what was signed.
 * The bytes that actually go into the HMAC come from buildCanonicalBytes: a JS string cannot hold
 * a body that is not UTF-8 text, and encoding one loses the distinction between the bytes.
 *
 * Payloads are type-checked because a template literal stringifies anything: without the guard a
 * JS caller signing ['a'], null or {} would get the signature for 'a', 'null' or
 * '[object Object]', and two callers that meant different things would collide.
 */
export function buildCanonicalString(timestamp: number, nonce: string, payload: string): string {
  const prefix = buildCanonicalPrefix(timestamp, nonce);
  if (typeof payload !== 'string') {
    throw new TypeError('payload must be a string');
  }
  return `${prefix}${payload}`;
}

/**
 * Builds the bytes that are HMAC'd: the prefix as UTF-8, then the payload as it stands.
 *
 * A string payload is UTF-8 encoded, so a JSON body signs to the same digest whether it is handed
 * over as text or as the bytes it arrived in. A Uint8Array is copied through untouched, which is
 * what makes the signature cover the exact bytes the sender put on the wire — UTF-8 encoding maps
 * every unpaired surrogate onto the same three bytes, so a string-only payload would let two
 * different bodies share one signature.
 */
export function buildCanonicalBytes(
  timestamp: number,
  nonce: string,
  payload: WebhookPayload,
): Buffer {
  const prefix = buildCanonicalPrefix(timestamp, nonce);
  if (typeof payload !== 'string' && !(payload instanceof Uint8Array)) {
    throw new TypeError('payload must be a string or a Uint8Array');
  }
  const payloadBytes = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  return Buffer.concat([Buffer.from(prefix, 'utf8'), payloadBytes]);
}
