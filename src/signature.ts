/**
 * Wire form of a signature: `{version}={hex}`, for example `v2=3f9a...`.
 *
 * The version travels with the signature so a receiver can dispatch on it (and refuse anything it
 * does not support) instead of assuming. The digest must be exactly 64 hex characters.
 * `Buffer.from(str, 'hex')` silently stops at the first non-hex pair, so without this guard a valid
 * signature with junk appended, or a folded duplicate header (`sigA, sigB`), would still verify.
 *
 * Either case is accepted, because a Go or Python sender formatting with %X is otherwise refused
 * with the same 401 as a forgery and has nothing to go on. The digest is lower-cased before it is
 * decoded, so nothing downstream ever compares the case that happened to arrive.
 */
export const SIGNATURE_PATTERN = /^(v[0-9]+)=([0-9a-fA-F]{64})$/;

export interface ParsedSignature {
  version: string;
  digest: Buffer;
}

export function formatSignature(version: string, digest: Buffer): string {
  return `${version}=${digest.toString('hex')}`;
}

/** Returns null for anything that is not exactly `{version}={64 hex}`. */
export function parseSignature(wire: string): ParsedSignature | null {
  if (typeof wire !== 'string') return null;
  const match = SIGNATURE_PATTERN.exec(wire);
  if (!match) return null;
  const hex = (match[2] as string).toLowerCase();
  return { version: match[1] as string, digest: Buffer.from(hex, 'hex') };
}
