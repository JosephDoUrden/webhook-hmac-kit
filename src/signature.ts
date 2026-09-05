import { SIGNATURE_VERSION } from './types.js';

/**
 * Wire form of a signature: `{version}={hex}`, for example `v2=3f9a...`.
 *
 * The version travels with the signature so a receiver can dispatch on it (and refuse anything it
 * does not support) instead of assuming. The digest must be exactly 64 lower-case hex characters.
 * `Buffer.from(str, 'hex')` silently stops at the first non-hex pair, so without this guard a valid
 * signature with junk appended, or a folded duplicate header (`sigA, sigB`), would still verify.
 *
 * Lower case only, so one digest has exactly one wire form. Accepting either case would give every
 * signature 2^64 spellings, and anything that treats the header as an opaque token — a replay cache
 * keyed on it, a rate limiter, a log line compared against another — would see them as different
 * values while the verifier saw them as one. A sender in another language must format with %x.
 */
export const SIGNATURE_PATTERN = /^(v[0-9]+)=([0-9a-f]{64})$/;

export interface ParsedSignature {
  version: string;
  digest: Buffer;
}

/**
 * Formats a digest for the wire in the scheme this library implements.
 *
 * The version is not a parameter. A caller that could pass one could put a version on the wire that
 * nothing here will ever accept, and the resulting 401 would look like a receiver bug.
 */
export function formatSignature(digest: Buffer): string {
  return `${SIGNATURE_VERSION}=${digest.toString('hex')}`;
}

/** Returns null for anything that is not exactly `{version}={64 lower-case hex}`. */
export function parseSignature(wire: string): ParsedSignature | null {
  if (typeof wire !== 'string') return null;
  const match = SIGNATURE_PATTERN.exec(wire);
  if (!match) return null;
  return { version: match[1] as string, digest: Buffer.from(match[2] as string, 'hex') };
}
