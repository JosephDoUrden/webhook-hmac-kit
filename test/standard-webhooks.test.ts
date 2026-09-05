import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { bytesEqual, fromBase64, toHex, utf8 } from '../src/bytes.js';
import { buildCanonicalBytes } from '../src/canonical.js';
import { getSubtle } from '../src/crypto.js';
import { WebhookError, WebhookSignatureError, WebhookTimestampError } from '../src/errors.js';
import { signWebhook } from '../src/signer.js';
import {
  buildStandardWebhooksBytes,
  parseStandardWebhooksSecret,
  signStandardWebhooks,
  verifyStandardWebhooks,
} from '../src/standard-webhooks.js';
import type { StandardWebhooksVector } from './standard-webhooks-vectors.js';
import {
  DOTTED_ID_SIGNATURE,
  GO_BYTE_PAYLOAD,
  IGNORED_VERSION_SIGNATURE,
  UNPADDED_SECRET,
  UNPADDED_SECRET_SIGNATURE,
  VECTOR_A,
  VECTOR_B,
  VECTOR_B_OVER_VECTOR_A_SIGNATURE,
  WRONG_KEY_SIGNATURE,
} from './standard-webhooks-vectors.js';

function headersFor(vector: StandardWebhooksVector, signature = vector.signature) {
  return {
    'webhook-id': vector.messageId,
    'webhook-timestamp': String(vector.timestamp),
    'webhook-signature': signature,
  };
}

/** Puts the clock on the vector's own timestamp so the tolerance window is not what is under test. */
function atVectorTime(timestamp: number): void {
  vi.useFakeTimers();
  vi.setSystemTime(timestamp * 1000);
}

describe('the pinned vectors', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it.each([VECTOR_A, VECTOR_B])('signs $name', async (vector) => {
    const headers = await signStandardWebhooks({
      secrets: vector.secret,
      messageId: vector.messageId,
      timestamp: vector.timestamp,
      payload: vector.payload,
    });

    expect(headers).toEqual({
      'webhook-id': vector.messageId,
      'webhook-timestamp': String(vector.timestamp),
      'webhook-signature': vector.signature,
    });
  });

  it.each([VECTOR_A, VECTOR_B])('verifies $name', async (vector) => {
    atVectorTime(vector.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: vector.secret,
        headers: headersFor(vector),
        payload: vector.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  // The space after the colon in vector A is part of the vector. A test that quietly normalised it
  // would still pass against our own signer and fail against every other implementation.
  it('depends on the exact bytes of the payload', async () => {
    atVectorTime(VECTOR_A.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: headersFor(VECTOR_A),
        payload: VECTOR_A.payload.replace(': ', ':'),
      }),
    ).rejects.toThrow(WebhookSignatureError);
  });

  it('signs the same digest from a string payload and from its UTF-8 bytes', async () => {
    const asBytes = await signStandardWebhooks({
      secrets: VECTOR_A.secret,
      messageId: VECTOR_A.messageId,
      timestamp: VECTOR_A.timestamp,
      payload: utf8(VECTOR_A.payload),
    });

    expect(asBytes['webhook-signature']).toBe(VECTOR_A.signature);
  });
});

describe('the signature list', () => {
  beforeEach(() => {
    atVectorTime(VECTOR_A.timestamp);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // Upstream's own multi-signature tests require a `v2,` entry to be SKIPPED rather than rejected,
  // so our behaviour here is externally specified. The malformed entry is ours: four of the five
  // reference libraries skip one, and the fifth (Python) crashes on it, which turns an
  // attacker-chosen header into a 500 instead of a 401.
  it('accepts a valid entry among an unknown tag, a wrong key and a malformed entry', async () => {
    const header = [
      WRONG_KEY_SIGNATURE,
      IGNORED_VERSION_SIGNATURE,
      'garbage',
      VECTOR_A.signature,
      'v1,!!!not-base64!!!',
    ].join(' ');

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: headersFor(VECTOR_A, header),
        payload: VECTOR_A.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it.each([
    ['an unknown tag on its own', IGNORED_VERSION_SIGNATURE],
    ['an entry with no comma', 'garbage'],
    ['an entry with no digest', 'v1,'],
    ['a digest that is not base64', 'v1,!!!not-base64!!!'],
    ['an empty header value made of spaces', '   '],
  ])('rejects a header carrying only %s', async (_name, header) => {
    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: headersFor(VECTOR_A, header),
        payload: VECTOR_A.payload,
      }),
    ).rejects.toThrow(WebhookSignatureError);
  });

  // A base64 value that decodes to anything but 32 bytes cannot be an HMAC-SHA256 digest, so it is
  // refused before any key is imported. The spy is the assertion: an attacker who can post a
  // hundred short signatures must not be able to make the receiver do a hundred HMACs.
  it('refuses a wrong-length digest before doing any crypto', async () => {
    const sign = vi.spyOn(getSubtle(), 'sign');
    const importKey = vi.spyOn(getSubtle(), 'importKey');

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: headersFor(VECTOR_A, 'v1,YWJj v1,YWJjZA=='),
        payload: VECTOR_A.payload,
      }),
    ).rejects.toThrow(WebhookSignatureError);

    expect(sign).toHaveBeenCalledTimes(0);
    expect(importKey).toHaveBeenCalledTimes(0);
  });

  // Every secret is weighed against every entry, whether or not an earlier pair matched. A break
  // out of either loop would say which position in the rotation the forgery got closest to.
  it('does the same work wherever the match is', async () => {
    const secrets = [VECTOR_B.secret, VECTOR_A.secret];
    const entries = [WRONG_KEY_SIGNATURE, VECTOR_A.signature, WRONG_KEY_SIGNATURE];

    const sign = vi.spyOn(getSubtle(), 'sign');

    await verifyStandardWebhooks({
      secrets,
      headers: headersFor(VECTOR_A, entries.join(' ')),
      payload: VECTOR_A.payload,
    });

    // One expected MAC per secret, then a blinding MAC over each side of every comparison.
    expect(sign).toHaveBeenCalledTimes(secrets.length * (1 + 2 * entries.length));
  });

  // Their rotation model: the sender emits one signature per live key and the receiver tries each.
  // Ours is the other way round, a list of keys on the receiver, and both work here because the
  // parser weighs every configured secret against every entry on the wire.
  it('emits one entry per secret, space-joined, in the order given', async () => {
    const headers = await signStandardWebhooks({
      secrets: [VECTOR_A.secret, VECTOR_B.secret],
      messageId: VECTOR_A.messageId,
      timestamp: VECTOR_A.timestamp,
      payload: VECTOR_A.payload,
    });

    expect(headers['webhook-signature']).toBe(
      `${VECTOR_A.signature} ${VECTOR_B_OVER_VECTOR_A_SIGNATURE}`,
    );
  });

  it('collapses a repeated secret into one entry', async () => {
    const headers = await signStandardWebhooks({
      secrets: [VECTOR_A.secret, 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'],
      messageId: VECTOR_A.messageId,
      timestamp: VECTOR_A.timestamp,
      payload: VECTOR_A.payload,
    });

    expect(headers['webhook-signature']).toBe(VECTOR_A.signature);
  });
});

describe('secrets', () => {
  it('strips the whsec_ prefix and decodes what is left', () => {
    expect(parseStandardWebhooksSecret(VECTOR_A.secret)).toHaveLength(24);
    expect(parseStandardWebhooksSecret('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw')).toHaveLength(24);
    expect(
      bytesEqual(
        parseStandardWebhooksSecret(VECTOR_A.secret),
        parseStandardWebhooksSecret('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'),
      ),
    ).toBe(true);
  });

  // The same string means two different keys in the two schemes: raw UTF-8 bytes for this
  // package's own scheme, base64 for Standard Webhooks. Bytes mean the same thing in both.
  it('takes a Uint8Array as raw key material', () => {
    const raw = Uint8Array.from({ length: 24 }, (_, i) => i);
    expect([...parseStandardWebhooksSecret(raw)]).toEqual([...raw]);
  });

  it('copies the bytes it was handed', () => {
    const raw = Uint8Array.from({ length: 24 }, (_, i) => i);
    const parsed = parseStandardWebhooksSecret(raw);
    raw[0] = 0xff;
    expect(parsed[0]).toBe(0);
  });

  it.each([
    ['a URL-safe alphabet', 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2La-aSw'],
    ['an underscore inside the base64', 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2La_aSw'],
    ['a value that is not base64 at all', 'whsec_not-a-base64-secret!'],
    ['a length that cannot be a base64 group', 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwB'],
    ['nothing after the prefix', 'whsec_'],
    ['an empty string', ''],
  ])('refuses %s', (_name, secret) => {
    expect(() => parseStandardWebhooksSecret(secret)).toThrow(TypeError);
  });

  it('refuses a type that is neither a string nor bytes', () => {
    expect(() => parseStandardWebhooksSecret(42 as unknown as string)).toThrow(TypeError);
    expect(() => parseStandardWebhooksSecret(null as unknown as string)).toThrow(TypeError);
  });

  // The spec states 24-64 bytes and no reference library enforces it. We enforce it where it is
  // ours to enforce - on the key we sign with - and not on receive, where the key was chosen by
  // whoever is sending to us.
  it.each([
    ['23 bytes', UNPADDED_SECRET],
    ['65 bytes', `whsec_${'A'.repeat(88)}`],
  ])('refuses a %s key on the sign path', (_name, secret) => {
    expect(() => parseStandardWebhooksSecret(secret, { usage: 'sign' })).toThrow(/24/);
  });

  it('accepts the same keys on the verify path', () => {
    expect(parseStandardWebhooksSecret(UNPADDED_SECRET, { usage: 'verify' })).toHaveLength(23);
    expect(parseStandardWebhooksSecret(`whsec_${'A'.repeat(88)}`)).toHaveLength(66);
  });
});

describe("the sign path's extra strictness", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('refuses the 23-byte Python fixture', () => {
    expect(() =>
      signStandardWebhooks({
        secrets: UNPADDED_SECRET,
        messageId: 'msg_1',
        timestamp: VECTOR_A.timestamp,
        payload: '{}',
      }),
    ).toThrow(/24/);
  });

  it('verifies against the same 23-byte key', async () => {
    atVectorTime(VECTOR_A.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: UNPADDED_SECRET,
        headers: {
          'webhook-id': 'msg_1',
          'webhook-timestamp': String(VECTOR_A.timestamp),
          'webhook-signature': UNPADDED_SECRET_SIGNATURE,
        },
        payload: '{}',
      }),
    ).resolves.toEqual({ valid: true });
  });

  // 'supersecret' is every bit as much valid base64 as a real key is: eleven characters from the
  // alphabet, decoding to eight bytes. Nothing on the receive side can tell it from a key someone
  // chose, so the only place it can be caught is where we are the ones signing.
  it('refuses a plausible-looking word as a signing key', () => {
    expect(parseStandardWebhooksSecret('supersecret')).toHaveLength(8);
    expect(() => parseStandardWebhooksSecret('supersecret', { usage: 'sign' })).toThrow(/24/);
  });

  // The dot is the field delimiter. An id holding one is legal for them and re-splittable for
  // everybody, so we refuse to emit it and still accept it on receive, where refusing would only
  // break interoperability without removing the ambiguity.
  it.each([
    ['a dot', 'msg.1'],
    ['a space', 'msg 1'],
    ['a tab', 'msg\t1'],
    ['a newline', 'msg\n1'],
    ['nothing at all', ''],
  ])('refuses a message id containing %s', (_name, messageId) => {
    expect(() =>
      signStandardWebhooks({
        secrets: VECTOR_A.secret,
        messageId,
        timestamp: VECTOR_A.timestamp,
        payload: '{}',
      }),
    ).toThrow(TypeError);
  });

  it('accepts a message id containing a dot on the verify path', async () => {
    atVectorTime(VECTOR_A.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: {
          'webhook-id': 'msg.with.dots',
          'webhook-timestamp': String(VECTOR_A.timestamp),
          'webhook-signature': DOTTED_ID_SIGNATURE,
        },
        payload: VECTOR_A.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  // Signing a body that is not well-formed UTF-8 produces a digest a JavaScript or Python receiver
  // computes differently, because both decode the body to a string first and collapse the bad
  // bytes onto U+FFFD. Refusing at send time turns a silent interop failure into a loud one.
  it('refuses a byte payload that is not well-formed UTF-8', () => {
    expect(() =>
      signStandardWebhooks({
        secrets: VECTOR_A.secret,
        messageId: 'msg_1',
        timestamp: VECTOR_A.timestamp,
        payload: Uint8Array.from([0x7b, 0xff, 0x7d]),
      }),
    ).toThrow(TypeError);
  });

  // TextEncoder maps every lone surrogate onto the same three replacement bytes, so two different
  // strings sign identically. That is the open upstream complaint against the reference JavaScript
  // library (its PR #261); we refuse the input instead of signing an ambiguous digest.
  it.each([
    ['a lone high surrogate', '{"a":"\uD800"}'],
    ['a lone low surrogate', '{"a":"\uDFFF"}'],
  ])('refuses a string payload holding %s', (_name, payload) => {
    expect(() =>
      signStandardWebhooks({
        secrets: VECTOR_A.secret,
        messageId: 'msg_1',
        timestamp: VECTOR_A.timestamp,
        payload,
      }),
    ).toThrow(TypeError);
  });

  it('validates synchronously rather than rejecting a promise', () => {
    expect(() =>
      signStandardWebhooks({
        secrets: [],
        messageId: 'msg_1',
        timestamp: VECTOR_A.timestamp,
        payload: '{}',
      }),
    ).toThrow('secrets must not be empty');
  });
});

/**
 * The verify path HMACs the raw bytes, which is Go's behaviour and the spec's plain reading. A
 * sender that mangled the body before signing it simply fails, which is the correct outcome.
 */
describe('the verify path takes the payload as bytes', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('verifies a Go-signed body that is not valid UTF-8', async () => {
    atVectorTime(GO_BYTE_PAYLOAD.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: GO_BYTE_PAYLOAD.secret,
        headers: {
          'webhook-id': GO_BYTE_PAYLOAD.messageId,
          'webhook-timestamp': String(GO_BYTE_PAYLOAD.timestamp),
          'webhook-signature': GO_BYTE_PAYLOAD.signature,
        },
        payload: GO_BYTE_PAYLOAD.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it('does not accept the same body decoded to a string first', async () => {
    atVectorTime(GO_BYTE_PAYLOAD.timestamp);

    await expect(
      verifyStandardWebhooks({
        secrets: GO_BYTE_PAYLOAD.secret,
        headers: {
          'webhook-id': GO_BYTE_PAYLOAD.messageId,
          'webhook-timestamp': String(GO_BYTE_PAYLOAD.timestamp),
          'webhook-signature': GO_BYTE_PAYLOAD.signature,
        },
        payload: new TextDecoder().decode(GO_BYTE_PAYLOAD.payload),
      }),
    ).rejects.toThrow(WebhookSignatureError);
  });
});

describe('the headers contract', () => {
  beforeEach(() => {
    atVectorTime(VECTOR_A.timestamp);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('lower-cases the names it is given', async () => {
    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: {
          'Webhook-Id': VECTOR_A.messageId,
          'WEBHOOK-TIMESTAMP': String(VECTOR_A.timestamp),
          'Webhook-Signature': VECTOR_A.signature,
        },
        payload: VECTOR_A.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it('accepts a single-entry array, as a header parser may hand one over', async () => {
    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: {
          'webhook-id': [VECTOR_A.messageId],
          'webhook-timestamp': [String(VECTOR_A.timestamp)],
          'webhook-signature': [VECTOR_A.signature],
        },
        payload: VECTOR_A.payload,
      }),
    ).resolves.toEqual({ valid: true });
  });

  it.each(['webhook-id', 'webhook-timestamp', 'webhook-signature'])(
    'refuses a duplicated %s',
    async (name) => {
      const headers: Record<string, string | string[]> = headersFor(VECTOR_A);
      headers[name] = [headers[name] as string, headers[name] as string];

      await expect(
        verifyStandardWebhooks({
          secrets: VECTOR_A.secret,
          headers,
          payload: VECTOR_A.payload,
        }),
      ).rejects.toThrow(WebhookError);
    },
  );

  it.each(['webhook-id', 'webhook-timestamp', 'webhook-signature'])(
    'treats an empty %s as missing',
    async (name) => {
      const headers: Record<string, string> = headersFor(VECTOR_A);
      headers[name] = '';

      await expect(
        verifyStandardWebhooks({
          secrets: VECTOR_A.secret,
          headers,
          payload: VECTOR_A.payload,
        }),
      ).rejects.toThrow(WebhookError);
    },
  );

  it.each(['webhook-id', 'webhook-timestamp', 'webhook-signature'])(
    'refuses an absent %s',
    async (name) => {
      const headers: Record<string, string> = headersFor(VECTOR_A);
      delete headers[name];

      await expect(
        verifyStandardWebhooks({
          secrets: VECTOR_A.secret,
          headers,
          payload: VECTOR_A.payload,
        }),
      ).rejects.toThrow(WebhookError);
    },
  );

  it('refuses two spellings of the same header name', async () => {
    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: {
          'webhook-id': VECTOR_A.messageId,
          'Webhook-Id': 'msg_other',
          'webhook-timestamp': String(VECTOR_A.timestamp),
          'webhook-signature': VECTOR_A.signature,
        },
        payload: VECTOR_A.payload,
      }),
    ).rejects.toThrow(WebhookError);
  });
});

describe('the timestamp', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // Upstream answers "Message timestamp too old" and "Message timestamp too new" separately, which
  // tells an unauthenticated caller which side of the window it is on. Ours is one error class,
  // one code and one message on both sides.
  it('answers the same way whether it is too old or too new', async () => {
    atVectorTime(VECTOR_A.timestamp);

    const errors: WebhookTimestampError[] = [];
    for (const skew of [-1000, 1000]) {
      const headers = headersFor(VECTOR_A);
      headers['webhook-timestamp'] = String(VECTOR_A.timestamp + skew);

      await verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers,
        payload: VECTOR_A.payload,
      }).catch((error: WebhookTimestampError) => errors.push(error));
    }

    expect(errors).toHaveLength(2);
    expect(errors[0]).toBeInstanceOf(WebhookTimestampError);
    expect(errors[0]?.code).toBe(errors[1]?.code);
    expect(errors[0]?.message).toBe(errors[1]?.message);
    expect(errors[0]?.constructor).toBe(errors[1]?.constructor);
  });

  it('honours a configured tolerance', async () => {
    atVectorTime(VECTOR_A.timestamp + 1000);

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers: headersFor(VECTOR_A),
        payload: VECTOR_A.payload,
        tolerance: 2000,
      }),
    ).resolves.toEqual({ valid: true });
  });

  // Upstream parses with parseInt (JavaScript) and float (Python), so '123abc' and '1.5e9' both
  // reach the window check. Ours is the value that was signed or nothing.
  it.each([
    ['trailing junk', '1614265330abc'],
    ['a leading zero', '01614265330'],
    ['exponent form', '1.614265330e9'],
    ['a leading plus', '+1614265330'],
    ['a negative value', '-1614265330'],
    ['whitespace', ' 1614265330'],
    ['a value past the safe integer range', '99999999999999999999'],
  ])('refuses a timestamp spelled with %s', async (_name, timestamp) => {
    atVectorTime(VECTOR_A.timestamp);

    const headers = headersFor(VECTOR_A);
    headers['webhook-timestamp'] = timestamp;

    await expect(
      verifyStandardWebhooks({
        secrets: VECTOR_A.secret,
        headers,
        payload: VECTOR_A.payload,
      }),
    ).rejects.toThrow(WebhookTimestampError);
  });
});

describe('the two schemes must never share key material', () => {
  // v2.{ts}.{nonce}.{payload} and a Standard Webhooks message whose id is literally 'v2' and whose
  // payload is '{nonce}.{payload}' are the same bytes. Domain separation would fix it and
  // conformance forbids it - the signed value is fixed by their spec - so the rule is that one key
  // is never used for both schemes, and this test is what keeps that rule honest.
  const nonce = 'nonce_abc123';
  const payload = '{"event":"payment.completed"}';
  const timestamp = 1700000000;
  const sharedKey = fromBase64('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw');

  it('builds identical canonical bytes across the two schemes', () => {
    expect(
      bytesEqual(
        buildCanonicalBytes(timestamp, nonce, payload),
        buildStandardWebhooksBytes('v2', timestamp, `${nonce}.${payload}`),
      ),
    ).toBe(true);
  });

  it('produces the same digest from one key under both schemes', async () => {
    const ours = await signWebhook({ secrets: sharedKey, payload, timestamp, nonce });
    const theirs = await signStandardWebhooks({
      secrets: sharedKey,
      messageId: 'v2',
      timestamp,
      payload: `${nonce}.${payload}`,
    });

    const theirDigest = fromBase64(theirs['webhook-signature'].slice('v1,'.length));
    expect(ours.signature).toBe(`v2=${toHex(theirDigest)}`);
  });
});

describe('the Standard Webhooks encoding is not injective', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // Their signed value is `{id}.{ts}.{payload}` with nothing constraining the id, so an id holding
  // a dot and a run of digits re-splits into a different, equally valid message with the same
  // signature. This is a property of their specification, not of this implementation, and it
  // cannot be fixed without emitting signatures no conforming receiver would accept.
  //
  // Written as a fixed example rather than a property on purpose: a property here would assert
  // that a collision exists, which reads like a goal. It is a known limitation, and the point of
  // pinning it is that nobody treats `webhook-id` as authenticated.
  const first = { messageId: 'msg_1.1700000000', timestamp: 1700000300, payload: 'body' };
  const second = { messageId: 'msg_1', timestamp: 1700000000, payload: '1700000300.body' };

  it('gives two different messages the same signed bytes', () => {
    expect(
      bytesEqual(
        buildStandardWebhooksBytes(first.messageId, first.timestamp, first.payload),
        buildStandardWebhooksBytes(second.messageId, second.timestamp, second.payload),
      ),
    ).toBe(true);
  });

  it('lets one signature verify as either of them', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(first.timestamp * 1000);

    const signed = await signStandardWebhooks({
      secrets: VECTOR_A.secret,
      messageId: second.messageId,
      timestamp: second.timestamp,
      payload: second.payload,
    });

    for (const message of [first, second]) {
      await expect(
        verifyStandardWebhooks({
          secrets: VECTOR_A.secret,
          headers: {
            'webhook-id': message.messageId,
            'webhook-timestamp': String(message.timestamp),
            'webhook-signature': signed['webhook-signature'],
          },
          payload: message.payload,
        }),
      ).resolves.toEqual({ valid: true });
    }
  });
});

describe('signing text and signing its bytes agree', () => {
  it('gives the same header for a string and for its UTF-8 encoding', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ unit: 'grapheme', maxLength: 64 }),
        fc.integer({ min: 0, max: 4102444800 }),
        async (payload, timestamp) => {
          const asText = await signStandardWebhooks({
            secrets: VECTOR_A.secret,
            messageId: VECTOR_A.messageId,
            timestamp,
            payload,
          });
          const asBytes = await signStandardWebhooks({
            secrets: VECTOR_A.secret,
            messageId: VECTOR_A.messageId,
            timestamp,
            payload: utf8(payload),
          });

          expect(asBytes).toEqual(asText);
        },
      ),
      { numRuns: 100 },
    );
  });
});
