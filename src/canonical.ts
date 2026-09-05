import { SIGNATURE_VERSION } from './types.js';

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
 * Builds the string that is HMAC'd:
 *
 *   v2.{timestamp}.{nonce}.{payload}
 *
 * The encoding is injective. The timestamp is a decimal integer and the nonce cannot contain '.',
 * so the first three fields are delimited without ambiguity and the payload is everything after the
 * third dot, bytes included, dots included. A decoder can always recover the exact (timestamp,
 * nonce, payload) triple, which is what lets the nonce serve as a replay-cache key.
 *
 * Throws on a malformed timestamp or nonce. Callers that need typed errors (the verifier) check
 * the fields first; this is the last line of defense.
 */
export function buildCanonicalString(timestamp: number, nonce: string, payload: string): string {
  if (!isValidTimestamp(timestamp)) {
    throw new TypeError('timestamp must be a non-negative safe integer (unix seconds)');
  }
  if (!isValidNonce(nonce)) {
    throw new TypeError('nonce must match ^[A-Za-z0-9_-]{1,64}$');
  }
  return `${SIGNATURE_VERSION}.${timestamp}.${nonce}.${payload}`;
}
