/**
 * Wire form of a signature: `{version}={hex}`, for example `v2=3f9a...`.
 *
 * The version travels with the signature so a receiver can dispatch on it (and refuse anything it
 * does not support) instead of assuming. The digest must be exactly 64 lower-case hex characters.
 * `Buffer.from(str, 'hex')` silently stops at the first non-hex pair, so without this guard a valid
 * signature with junk appended, or a folded duplicate header (`sigA, sigB`), would still verify.
 */
export const SIGNATURE_PATTERN = /^(v[0-9]+)=([0-9a-f]{64})$/;

export interface ParsedSignature {
  version: string;
  digest: Buffer;
}

export function formatSignature(version: string, digest: Buffer): string {
  return `${version}=${digest.toString('hex')}`;
}

/** Returns null for anything that is not exactly `{version}={64 lower-case hex}`. */
export function parseSignature(wire: string): ParsedSignature | null {
  if (typeof wire !== 'string') return null;
  const match = SIGNATURE_PATTERN.exec(wire);
  if (!match) return null;
  return { version: match[1] as string, digest: Buffer.from(match[2] as string, 'hex') };
}
