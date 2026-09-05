import { describe, expect, it } from 'vitest';
import { bytesEqual, concat, fromBase64, fromHex, toBase64, toHex, utf8 } from '../src/bytes.js';

describe('utf8', () => {
  it('encodes ASCII one byte per character', () => {
    expect([...utf8('abc')]).toEqual([0x61, 0x62, 0x63]);
  });

  it('encodes an empty string as no bytes', () => {
    expect(utf8('')).toHaveLength(0);
  });

  it('encodes beyond the BMP', () => {
    expect([...utf8('🚀')]).toEqual([0xf0, 0x9f, 0x9a, 0x80]);
  });

  // The library signs bytes precisely because this mapping is lossy. Pinning it here says the loss
  // is the encoder's, so nothing upstream has to guess whether it happened.
  it('maps every unpaired surrogate onto the same replacement bytes', () => {
    expect([...utf8('\uD800')]).toEqual([0xef, 0xbf, 0xbd]);
    expect([...utf8('\uDFFF')]).toEqual([0xef, 0xbf, 0xbd]);
  });

  it('returns a plain Uint8Array, not a subclass', () => {
    expect(utf8('a').constructor).toBe(Uint8Array);
  });
});

describe('concat', () => {
  it('joins parts in order', () => {
    const joined = concat(Uint8Array.from([1, 2]), Uint8Array.from([3]), Uint8Array.from([4, 5]));
    expect([...joined]).toEqual([1, 2, 3, 4, 5]);
  });

  it('handles no parts and empty parts', () => {
    expect(concat()).toHaveLength(0);
    expect([...concat(new Uint8Array(0), Uint8Array.from([7]), new Uint8Array(0))]).toEqual([7]);
  });

  it('copies rather than aliasing its inputs', () => {
    const part = Uint8Array.from([1, 2]);
    const joined = concat(part);
    part[0] = 9;
    expect([...joined]).toEqual([1, 2]);
  });

  // A Uint8Array can be a window onto a larger buffer. Reading through .buffer rather than the
  // view would splice in bytes the caller never passed.
  it('respects a byte offset into a larger buffer', () => {
    const backing = Uint8Array.from([1, 2, 3, 4, 5]);
    const window = backing.subarray(1, 3);
    expect([...concat(window)]).toEqual([2, 3]);
  });
});

describe('toHex', () => {
  it('renders lower-case, two characters per byte', () => {
    expect(toHex(Uint8Array.from([0x00, 0x0f, 0xa0, 0xff]))).toBe('000fa0ff');
  });

  it('renders no bytes as an empty string', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
  });

  it('round-trips every byte value', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect([...fromHex(toHex(all))]).toEqual([...all]);
  });
});

describe('fromHex', () => {
  it('decodes lower-case hex', () => {
    expect([...fromHex('000fa0ff')]).toEqual([0x00, 0x0f, 0xa0, 0xff]);
  });

  it('decodes an empty string to no bytes', () => {
    expect(fromHex('')).toHaveLength(0);
  });

  // Buffer.from(str, 'hex') stops silently at the first thing it cannot read, so 'ffzz' decodes to
  // one byte and a signature with junk appended still parses. Everything below has to throw.
  it.each([
    ['an odd length', 'abc'],
    ['a single character', 'a'],
    ['upper-case hex', 'AB'],
    ['a mixed-case pair', 'aB'],
    ['a non-hex letter', 'zz'],
    ['trailing junk', 'ffzz'],
    ['leading junk', 'zzff'],
    ['whitespace', 'ff '],
    ['a 0x prefix', '0xff'],
    ['a unicode digit that Number() would accept', '０１'],
  ])('refuses %s', (_name, hex) => {
    expect(() => fromHex(hex)).toThrow(/hex/i);
  });

  it('refuses anything that is not a string', () => {
    expect(() => fromHex(null as unknown as string)).toThrow(/hex/i);
    expect(() => fromHex(255 as unknown as string)).toThrow(/hex/i);
  });
});

describe('bytesEqual', () => {
  it('compares contents, not identity', () => {
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 2]))).toBe(true);
    expect(bytesEqual(Uint8Array.from([1, 2]), Uint8Array.from([1, 3]))).toBe(false);
  });

  it('treats different lengths as unequal', () => {
    expect(bytesEqual(Uint8Array.from([1]), Uint8Array.from([1, 0]))).toBe(false);
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('does not confuse a prefix with the whole', () => {
    expect(bytesEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2]))).toBe(false);
  });
});

describe('toBase64', () => {
  it('renders the standard alphabet with padding', () => {
    expect(toBase64(utf8('a'))).toBe('YQ==');
    expect(toBase64(utf8('ab'))).toBe('YWI=');
    expect(toBase64(utf8('abc'))).toBe('YWJj');
  });

  it('renders no bytes as an empty string', () => {
    expect(toBase64(new Uint8Array(0))).toBe('');
  });

  // Standard Webhooks signatures are standard-alphabet base64. URL-safe output would be silently
  // unverifiable everywhere, because nothing in that ecosystem accepts '-' or '_'.
  it('uses + and / rather than the URL-safe pair', () => {
    expect(toBase64(Uint8Array.from([0xfb, 0xff, 0xbf]))).toBe('+/+/');
  });

  it('round-trips every byte value', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect([...fromBase64(toBase64(all))]).toEqual([...all]);
  });

  it('reads through a byte offset rather than the whole backing buffer', () => {
    const backing = Uint8Array.from([1, 2, 3, 4, 5]);
    expect(toBase64(backing.subarray(1, 3))).toBe(toBase64(Uint8Array.from([2, 3])));
  });
});

describe('fromBase64', () => {
  it('decodes padded input', () => {
    expect([...fromBase64('YWJj')]).toEqual([0x61, 0x62, 0x63]);
    expect([...fromBase64('YQ==')]).toEqual([0x61]);
    expect([...fromBase64('YWI=')]).toEqual([0x61, 0x62]);
  });

  // Python's b64decode(secret + '==') accepts an unpadded whsec_ secret and one of the upstream
  // test fixtures depends on it, so a receiver that refused unpadded input would reject a secret
  // a Python sender is happily signing with.
  it('decodes unpadded input', () => {
    expect([...fromBase64('YQ')]).toEqual([0x61]);
    expect([...fromBase64('YWI')]).toEqual([0x61, 0x62]);
  });

  it('decodes an empty string to no bytes', () => {
    expect(fromBase64('')).toHaveLength(0);
  });

  // Everything here decodes to something plausible under a lenient decoder. Buffer.from(s,'base64')
  // returns bytes for all of them, which is how a mistyped secret becomes a key nobody chose.
  it.each([
    ['a URL-safe minus', 'YW-j'],
    ['a URL-safe underscore', 'YW_j'],
    ['a length that cannot be a group', 'YWJjY'],
    ['padding in the middle', 'YQ==YQ=='],
    ['three padding characters', 'YQ==='],
    ['padding on a full group', 'YWJj='],
    ['padding alone', '='],
    ['inner whitespace', 'YW Jj'],
    ['trailing whitespace', 'YWJj '],
    ['a newline', 'YWJj\n'],
    ['a character outside the alphabet', 'YW!j'],
    ['a unicode digit that Number() would accept', '０１２３'],
  ])('refuses %s', (_name, text) => {
    expect(() => fromBase64(text)).toThrow(/base64/i);
  });

  // The bits below the last whole byte are not required to be zero, which is the one place this
  // decoder is deliberately lenient. Both unpadded secrets in the upstream Python fixture set them,
  // so refusing them would refuse a key a Python sender is signing with. 'YQ' and 'YR' therefore
  // both mean 0x61; that is survivable because callers compare decoded bytes and nothing treats the
  // base64 text as an identity.
  it('keeps non-canonical trailing bits decodable', () => {
    expect([...fromBase64('YR==')]).toEqual([0x61]);
    expect([...fromBase64('YR')]).toEqual([0x61]);
    expect(fromBase64('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS')).toHaveLength(23);
  });

  it('refuses anything that is not a string', () => {
    expect(() => fromBase64(null as unknown as string)).toThrow(/base64/i);
    expect(() => fromBase64(255 as unknown as string)).toThrow(/base64/i);
  });
});
