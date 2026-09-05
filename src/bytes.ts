/**
 * The four byte operations this library needs, written out rather than borrowed.
 *
 * Buffer is a Node type. Uint8Array.prototype.toHex and Uint8Array.fromHex would be the obvious
 * replacements and are not available: they landed in Node 25, so the current Active LTS (24) does
 * not have them, and neither do the older lines this package supports. Feature-detecting them would
 * ship two implementations of which the fallback is the one production actually runs — so there is
 * one implementation, and it is this one. atob/btoa are ruled out for the same reason plus their
 * own: they speak in latin-1 code units, not bytes.
 *
 * None of this is on a hot path. A webhook does one HMAC and formats 32 bytes.
 */

/** Shared instance. Constructing a TextEncoder allocates nothing interesting and it is stateless. */
const ENCODER = new TextEncoder();

const BYTE_TO_HEX: readonly string[] = Array.from({ length: 256 }, (_, byte) =>
  byte.toString(16).padStart(2, '0'),
);

/**
 * Even-length, lower-case hex and nothing else.
 *
 * Upper case is refused here as it is on the wire: accepting either case would give one digest
 * 2^64 spellings, and anything treating the signature header as an opaque token would see them as
 * different values while the verifier saw them as one.
 */
const LOWER_HEX_PAIRS = /^(?:[0-9a-f]{2})*$/;

/**
 * UTF-8 encodes a string.
 *
 * Lossy by definition: every unpaired surrogate encodes to the same three replacement bytes, which
 * is exactly why payloads and secrets that are not text have to arrive as bytes.
 */
export function utf8(text: string): Uint8Array {
  return ENCODER.encode(text);
}

/** Joins byte runs into one fresh array. Copies, so a later write to a part is not visible here. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

/** Lower-case hex, two characters per byte, no separators. */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += BYTE_TO_HEX[byte] as string;
  }
  return hex;
}

/**
 * Decodes lower-case hex, or throws.
 *
 * Strict on purpose. Buffer.from(str, 'hex') stops at the first pair it cannot read and returns
 * what it managed, so a signature with junk appended, or a folded duplicate header value
 * ('sigA, sigB'), decodes to a plausible-looking digest instead of being refused. Callers reaching
 * this function have usually already been through SIGNATURE_PATTERN, which enforces the same
 * alphabet; this is the second lock, for anyone who has not.
 */
export function fromHex(hex: string): Uint8Array {
  if (typeof hex !== 'string' || !LOWER_HEX_PAIRS.test(hex)) {
    throw new TypeError('expected an even-length string of lower-case hex characters');
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    // The alphabet is already fixed to [0-9a-f], so a digit is code - '0' and a letter is
    // code - ('a' - 10). No table, no branch on anything the regex has not already settled.
    const high = hexDigit(hex.charCodeAt(i * 2));
    const low = hexDigit(hex.charCodeAt(i * 2 + 1));
    bytes[i] = (high << 4) | low;
  }
  return bytes;
}

function hexDigit(code: number): number {
  return code <= 0x39 ? code - 0x30 : code - 0x57;
}

/**
 * Content equality for byte runs.
 *
 * Not constant time, and never to be used on anything secret: it exits at the first difference and
 * at a length mismatch, both of which are measurable. It exists for collapsing a list of configured
 * secrets, where every value came from the receiver's own configuration and nothing an attacker
 * supplies reaches it. Comparing a presented MAC against an expected one goes through
 * blindedEqual in crypto.ts instead.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
