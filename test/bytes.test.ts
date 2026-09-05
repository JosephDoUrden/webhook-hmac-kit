import { describe, expect, it } from 'vitest';
import { bytesEqual, concat, fromHex, toHex, utf8 } from '../src/bytes.js';

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
