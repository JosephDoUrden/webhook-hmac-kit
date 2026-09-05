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

/**
 * Standard base64. Not the URL-safe variant: Standard Webhooks signatures and `whsec_` secrets are
 * both spelled with '+' and '/', and nothing in that ecosystem accepts '-' or '_'.
 */
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Character code to sextet, for the 128 codes that can appear. Everything else is -1. */
const BASE64_VALUE: readonly number[] = (() => {
  const table = new Array<number>(128).fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i++) {
    table[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/**
 * The alphabet, then at most two padding characters, and nothing else.
 *
 * Padding is optional here because it is optional in practice: Python's b64decode(secret + '==')
 * makes an unpadded `whsec_` secret work, and one of the upstream Standard Webhooks fixtures
 * depends on that. The group-length and trailing-bit rules below are what keep it strict.
 */
const BASE64_GRAMMAR = /^[A-Za-z0-9+/]*={0,2}$/;

/** One sextet of a 24-bit group, as its alphabet character. */
function sextet(group: number, shift: number): string {
  return BASE64_ALPHABET[(group >> shift) & 63] as string;
}

/** Standard-alphabet base64, padded to a multiple of four. */
export function toBase64(bytes: Uint8Array): string {
  let text = '';

  for (let i = 0; i < bytes.length; i += 3) {
    const remaining = bytes.length - i;
    const group =
      ((bytes[i] as number) << 16) |
      ((remaining > 1 ? (bytes[i + 1] as number) : 0) << 8) |
      (remaining > 2 ? (bytes[i + 2] as number) : 0);

    text += sextet(group, 18) + sextet(group, 12);
    text += remaining > 1 ? sextet(group, 6) : '=';
    text += remaining > 2 ? sextet(group, 0) : '=';
  }
  return text;
}

/**
 * Decodes standard-alphabet base64, or throws.
 *
 * Strict in the three ways the platform decoders are not, and each one has cost somebody a key.
 *
 * The alphabet is fixed, so a URL-safe secret is refused rather than quietly re-read: Python's
 * b64decode with validate=False drops every out-of-alphabet character and hands back bytes, which
 * is how 'not-a-base64-secret!' becomes a twelve-byte key nobody chose while Go and Rust reject
 * the same string outright.
 *
 * The character count has to be a possible group length. A trailing character with no room to
 * carry a byte ('YWJjY') means the value was truncated in transit, and a decoder that ignores it
 * returns a prefix of the intended key.
 *
 * What it does not refuse is a non-zero bit below the last whole byte, and that is deliberate
 * rather than an oversight. Both unpadded secrets in the upstream Python fixture carry them
 * ('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS' ends 'S', low two bits 10), so the rule that keeps fromHex
 * lower-case only would here reject a secret a Python sender is signing with. The cost is bounded:
 * callers compare decoded bytes, so a non-canonical spelling of a digest decodes to the same
 * value it would have anyway, and nothing here treats the base64 text as an identity.
 */
export function fromBase64(text: string): Uint8Array {
  if (typeof text !== 'string' || !BASE64_GRAMMAR.test(text)) {
    throw new TypeError('expected standard-alphabet base64 (A-Z a-z 0-9 + / and = padding)');
  }

  const padding = text.length - text.replace(/=+$/, '').length;
  const body = text.slice(0, text.length - padding);
  if (padding > 0 ? (body.length + padding) % 4 !== 0 : body.length % 4 === 1) {
    throw new TypeError('base64 length is not a whole number of four-character groups');
  }

  const bytes = new Uint8Array((body.length * 6) >> 3);
  let accumulator = 0;
  let bits = 0;
  let byteIndex = 0;

  for (let i = 0; i < body.length; i++) {
    accumulator = (accumulator << 6) | (BASE64_VALUE[body.charCodeAt(i)] as number);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[byteIndex++] = (accumulator >> bits) & 0xff;
    }
  }

  return bytes;
}
