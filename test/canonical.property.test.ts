import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { NONCE_PATTERN, buildCanonicalString } from '../src/canonical.js';
import { WebhookNonceError } from '../src/errors.js';
import { signWebhook } from '../src/signer.js';
import { verifyWebhook } from '../src/verifier.js';
import { TEST_SECRET } from './vectors.js';

// Injectivity of the canonical encoding is what makes the nonce usable as a replay-cache key.
// v1 (`v1:{ts}:{nonce}:{payload}`) was not injective: nonce and payload were both free-form and
// adjacent, so one signed message could be re-split into several (nonce, payload) pairs that all
// verified. v2 puts the strict-integer timestamp between a dot-free nonce and the payload.
//
// The property that matters is over the signature, not over the canonical string. The string is a
// string -> string map that was injective even while the bytes handed to the HMAC were not.

interface Fields {
  timestamp: number;
  nonce: string;
  payload: string;
}

interface SignableFields {
  timestamp: number;
  nonce: string;
  payload: string | Uint8Array;
}

// fc.nat({max: MAX_SAFE_INTEGER}) biases so hard towards small values that a plausible epoch
// second is almost never drawn, so the realistic range gets its own arm alongside the edge.
const timestampArb = fc.oneof(
  fc.integer({ min: 0, max: 4102444800 }),
  fc.nat({ max: Number.MAX_SAFE_INTEGER }),
);
const nonceArb = fc.stringMatching(NONCE_PATTERN);

// A grapheme unit is well formed by construction, so it never produces an unpaired surrogate and
// the encoding of ill-formed text goes untested. This unit reaches it.
const payloadUnitArb = fc.constantFrom('a', '.', ' ', '�', '\uD800', '\uDFFF');

// Payloads biased towards the characters that could confuse a delimiter-based parser:
// dots, digits, colons, and things that look like a nonce or a version tag.
const payloadArb = fc
  .array(
    fc.oneof(
      fc.constant('.'),
      fc.constant(':'),
      fc.constant('v2.'),
      fc.nat({ max: 99999 }).map(String),
      nonceArb,
      fc.string({ unit: payloadUnitArb, maxLength: 8 }),
      fc.string({ unit: 'grapheme', maxLength: 8 }),
    ),
    { maxLength: 24 },
  )
  .map((parts) => parts.join(''));

const fieldsArb: fc.Arbitrary<Fields> = fc.record({
  timestamp: timestampArb,
  nonce: nonceArb,
  payload: payloadArb,
});

// Two byte payloads drawn at random practically never decode to the same text, so the second arm
// draws from lead bytes that are invalid UTF-8 on their own: every one of them decodes to the same
// replacement character, which is what a byte payload has to survive.
const payloadBytesArb = fc.oneof(
  fc.uint8Array({ maxLength: 24 }),
  fc.uint8Array({ min: 0xf8, max: 0xff, maxLength: 4 }),
);

const signablePayloadArb = fc.oneof<fc.Arbitrary<string | Uint8Array>[]>(
  payloadArb,
  payloadBytesArb,
);

const signableFieldsArb: fc.Arbitrary<SignableFields> = fc.record({
  timestamp: timestampArb,
  nonce: nonceArb,
  payload: signablePayloadArb,
});

// The second triple starts from the first and overrides some of its fields. Two independently
// drawn triples practically never share a timestamp and a nonce, so the payload alone could never
// be the difference between them and a payload collision would never be reached.
const triplePairArb: fc.Arbitrary<[SignableFields, SignableFields]> = fc
  .record({
    base: signableFieldsArb,
    timestamp: fc.option(timestampArb, { nil: undefined }),
    nonce: fc.option(nonceArb, { nil: undefined }),
    payload: fc.option(signablePayloadArb, { nil: undefined }),
  })
  .map(({ base, timestamp, nonce, payload }) => [
    base,
    {
      timestamp: timestamp ?? base.timestamp,
      nonce: nonce ?? base.nonce,
      payload: payload ?? base.payload,
    },
  ]);

// Test-side decoder. If build has a left inverse it is injective by construction.
function decode(canonical: string): Fields | null {
  const match = /^v2\.(\d+)\.([A-Za-z0-9_-]{1,64})\.([\s\S]*)$/.exec(canonical);
  if (!match) return null;
  return {
    timestamp: Number(match[1]),
    nonce: match[2] as string,
    payload: match[3] as string,
  };
}

// A payload's identity is its bytes. A string is UTF-8 text, so 'a' and the byte 0x61 are the same
// message; two byte payloads that would decode to the same replacement character are not.
function payloadBytes(payload: string | Uint8Array): Buffer {
  return typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload);
}

function sameMessage(a: SignableFields, b: SignableFields): boolean {
  return (
    a.timestamp === b.timestamp &&
    a.nonce === b.nonce &&
    payloadBytes(a.payload).equals(payloadBytes(b.payload))
  );
}

function sign(fields: SignableFields): string {
  return signWebhook({ secrets: TEST_SECRET, ...fields }).signature;
}

describe('canonical encoding is injective', () => {
  it('gives distinct signatures to distinct (timestamp, nonce, payload) triples', () => {
    fc.assert(
      fc.property(triplePairArb, ([a, b]) => {
        fc.pre(!sameMessage(a, b));
        expect(sign(a)).not.toBe(sign(b));
      }),
      { numRuns: 2000 },
    );
  });

  it('signs a string payload and its UTF-8 bytes identically', () => {
    fc.assert(
      fc.property(fieldsArb, (fields) => {
        expect(sign({ ...fields, payload: Buffer.from(fields.payload, 'utf8') })).toBe(
          sign(fields),
        );
      }),
      { numRuns: 1000 },
    );
  });

  it('decodes back to the exact fields it was built from (left inverse)', () => {
    fc.assert(
      fc.property(fieldsArb, (fields) => {
        const canonical = buildCanonicalString(fields.timestamp, fields.nonce, fields.payload);
        expect(decode(canonical)).toEqual(fields);
      }),
      { numRuns: 2000 },
    );
  });

  it('moving the nonce/payload split to any other dot yields a nonce the grammar rejects', () => {
    fc.assert(
      fc.property(fieldsArb, (fields) => {
        const canonical = buildCanonicalString(fields.timestamp, fields.nonce, fields.payload);
        const rest = canonical.slice(`v2.${fields.timestamp}.`.length);

        for (let i = 0; i < rest.length; i++) {
          if (rest[i] !== '.') continue;
          const nonce = rest.slice(0, i);
          const payload = rest.slice(i + 1);
          if (nonce === fields.nonce) {
            expect(payload).toBe(fields.payload);
          } else {
            expect(NONCE_PATTERN.test(nonce)).toBe(false);
          }
        }
      }),
      { numRuns: 2000 },
    );
  });

  it('a signed message cannot be re-split into a different (nonce, payload) that verifies', async () => {
    const timestamp = Math.floor(Date.now() / 1000);

    await fc.assert(
      fc.asyncProperty(nonceArb, payloadArb, async (nonce, payload) => {
        const { signature } = signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce });
        const rest = `${nonce}.${payload}`;

        for (let i = 0; i < rest.length; i++) {
          if (rest[i] !== '.' || i === nonce.length) continue;
          await expect(
            verifyWebhook({
              secrets: TEST_SECRET,
              payload: rest.slice(i + 1),
              signature,
              timestamp,
              nonce: rest.slice(0, i),
            }),
          ).rejects.toThrow(WebhookNonceError);
        }
      }),
      { numRuns: 500 },
    );
  });
});

describe('the v1 collision (audit finding 1) no longer verifies', () => {
  it('re-splitting at a colon is rejected because the nonce grammar forbids colons', async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const { signature } = signWebhook({
      secrets: TEST_SECRET,
      payload: 'a:b:c',
      timestamp,
      nonce: 'abc',
    });

    for (const [nonce, payload] of [
      ['abc:a', 'b:c'],
      ['abc:a:b', 'c'],
    ] as const) {
      await expect(
        verifyWebhook({ secrets: TEST_SECRET, payload, signature, timestamp, nonce }),
      ).rejects.toThrow(WebhookNonceError);
    }
  });

  it('re-splitting at a dot is rejected for the same reason', async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const { signature } = signWebhook({
      secrets: TEST_SECRET,
      payload: 'a.b.c',
      timestamp,
      nonce: 'abc',
    });

    for (const [nonce, payload] of [
      ['abc.a', 'b.c'],
      ['abc.a.b', 'c'],
    ] as const) {
      await expect(
        verifyWebhook({ secrets: TEST_SECRET, payload, signature, timestamp, nonce }),
      ).rejects.toThrow(WebhookNonceError);
    }
  });

  it('a replay cache keyed on the nonce now fires on every redelivery', async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const seen = new Set<string>();
    const nonceValidator = async (nonce: string): Promise<boolean> => {
      if (seen.has(nonce)) return false;
      seen.add(nonce);
      return true;
    };

    const nonce = 'abc';
    const payload = 'a.b:c';
    const { signature } = signWebhook({ secrets: TEST_SECRET, payload, timestamp, nonce });

    await expect(
      verifyWebhook({ secrets: TEST_SECRET, payload, signature, timestamp, nonce, nonceValidator }),
    ).resolves.toEqual({ valid: true });

    await expect(
      verifyWebhook({ secrets: TEST_SECRET, payload, signature, timestamp, nonce, nonceValidator }),
    ).rejects.toThrow(/replay/i);

    for (const [n, p] of [
      ['abc.a', 'b:c'],
      ['abc.a.b', ':c'],
    ] as const) {
      await expect(
        verifyWebhook({
          secrets: TEST_SECRET,
          payload: p,
          signature,
          timestamp,
          nonce: n,
          nonceValidator,
        }),
      ).rejects.toThrow(WebhookNonceError);
    }
    expect(seen.size).toBe(1);
  });
});
