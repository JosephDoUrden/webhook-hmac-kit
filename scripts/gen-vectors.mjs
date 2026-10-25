#!/usr/bin/env node
/**
 * Writes vectors/standard-webhooks.json and vectors/v2.json.
 *
 *   node scripts/gen-vectors.mjs
 *
 * Every signature is computed here with node:crypto and nothing else. This script never imports
 * the package, so the corpus is a pin the library has to meet rather than a record of whatever the
 * library happened to produce. Values that came from somewhere else (the upstream reference
 * suites, the known answer from standard-webhooks#348, this repo's own fixtures) are written down
 * below and recomputed, and the script fails instead of writing if any recomputation disagrees.
 *
 * The output is deterministic: no dates, no randomness, keys in a fixed order. Running it twice
 * gives the same bytes, so a regenerated file can be diffed against the committed one.
 *
 * The files are laid out by JSON.stringify and nothing else. biome.json turns its formatter off for
 * vectors/** because it would fold short arrays onto one line, and then this script and the
 * formatter would each keep rewriting what the other wrote. Linting still runs over them.
 */

import { createHmac } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SELF = 'scripts/gen-vectors.mjs';
const TOLERANCE = 300;
const NOTE = 'Public test keys. Never use outside tests.';

/** standard-webhooks/standard-webhooks at main, 31 Aug 2026. Same pin as the TS fixtures. */
const UPSTREAM = 'standard-webhooks/standard-webhooks@7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b';
const UPSTREAM_JS_TEST = `${UPSTREAM}:libraries/javascript/src/webhook.test.ts`;

const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

function payloadOf(bytes) {
  const out = { base64: Buffer.from(bytes).toString('base64') };
  try {
    out.utf8 = FATAL_UTF8.decode(bytes);
  } catch {
    // Not text. The base64 is the payload; there is no string form to document.
  }
  return out;
}

function isUtf8(bytes) {
  try {
    FATAL_UTF8.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * What a case asks of the code under test. A valid case is signed and verified when its body is
 * text and only verified when it is not; a case that must fail at verify is verify-only, and one
 * that must be refused at sign is sign-only. Any other pairing contradicts itself.
 */
function directionFor(name, payload, expect, explicit) {
  const reject = typeof expect === 'object' && 'reject' in expect ? expect.reject : undefined;
  const fallback =
    reject === 'sign'
      ? 'sign-only'
      : expect === 'valid' && isUtf8(payload)
        ? 'sign+verify'
        : 'verify-only';
  const direction = explicit ?? fallback;
  const allowed =
    expect === 'valid'
      ? ['sign+verify', 'verify-only']
      : [reject === 'sign' ? 'sign-only' : 'verify-only'];
  if (!allowed.includes(direction)) {
    throw new Error(`${name}: direction ${direction} contradicts expect ${JSON.stringify(expect)}`);
  }
  if (direction === 'sign+verify' && !isUtf8(payload)) {
    throw new Error(`${name}: a payload that is not UTF-8 can only be verify-only`);
  }
  return direction;
}

function pinned(name, computed, expected) {
  if (computed !== expected) {
    throw new Error(`${name}: recomputed ${computed}, pinned ${expected}. Not writing.`);
  }
  return computed;
}

// --- Standard Webhooks -------------------------------------------------------------------------

function swKey(secret) {
  return Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
}

function swSign(secret, messageId, timestamp, payload) {
  const mac = createHmac('sha256', swKey(secret));
  mac.update(Buffer.from(`${messageId}.${timestamp}.`, 'utf8'));
  mac.update(payload);
  return `v1,${mac.digest('base64')}`;
}

const A = {
  secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  messageId: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
  timestamp: 1614265330,
  payload: Buffer.from('{"test": 2432232314}', 'utf8'),
};
const B = {
  secret: 'whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD',
  messageId: 'msg_27UH4WbU6Z5A5EzD8u03UvzRbpk',
  timestamp: 1649367553,
  payload: Buffer.from('{"email":"test@example.com","username":"test_user"}', 'utf8'),
};
const UNPADDED_SECRET = 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS';

const SIG_A = pinned(
  'vector A',
  swSign(A.secret, A.messageId, A.timestamp, A.payload),
  'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
);
const SIG_B = pinned(
  'vector B',
  swSign(B.secret, B.messageId, B.timestamp, B.payload),
  'v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=',
);
const WRONG_KEY = 'v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=';
const IGNORED_TAG = 'v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=';

function swCase(fields) {
  const {
    name,
    secrets,
    messageId,
    timestamp,
    payload,
    signature,
    now = timestamp,
    expect = 'valid',
    conformance = 'spec',
    source = SELF,
  } = fields;
  const direction = directionFor(name, payload, expect, fields.direction);
  return {
    name,
    conformance,
    ...(secrets.length === 1 ? { secret: secrets[0] } : { secrets }),
    messageId,
    timestamp,
    payload: payloadOf(payload),
    headers: {
      'webhook-id': messageId,
      'webhook-timestamp': String(timestamp),
      'webhook-signature': signature,
    },
    direction,
    now,
    expect,
    source,
  };
}

const allBytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
const goBytes = Buffer.from([0x7b, 0xff, 0x7d]);
const loneFF = Buffer.from([0xff]);
const replacement = Buffer.from('\uFFFD', 'utf8');
const dottedId = 'msg.with.dots';
const emptyObject = Buffer.from('{}', 'utf8');

const sigFF = swSign(A.secret, A.messageId, A.timestamp, loneFF);
const sigFFFD = swSign(A.secret, A.messageId, A.timestamp, replacement);
if (sigFF === sigFFFD) {
  throw new Error('0xff and U+FFFD signed to the same value; the corpus would prove nothing');
}

const sixteenWrong = Array.from({ length: 16 }, () => WRONG_KEY);

const standardWebhooks = {
  scheme: 'standard-webhooks',
  version: 1,
  note: NOTE,
  generated: SELF,
  tolerance: TOLERANCE,
  cases: [
    swCase({
      name: 'the six-language de-facto vector',
      secrets: [A.secret],
      ...A,
      signature: SIG_A,
      source: `${UPSTREAM_JS_TEST}:206-211`,
    }),
    swCase({
      name: "the Rust crate's vector",
      secrets: [B.secret],
      ...B,
      signature: SIG_B,
      source: `${UPSTREAM}:libraries/rust/src/lib.rs:190-201`,
    }),
    swCase({
      name: 'a byte payload that is not UTF-8, signed over the bytes',
      secrets: [A.secret],
      messageId: 'msg_bytes',
      timestamp: A.timestamp,
      payload: goBytes,
      signature: pinned(
        'Go bytes',
        swSign(A.secret, 'msg_bytes', A.timestamp, goBytes),
        'v1,D7UbbA/lAk3cw4K7TmhocB2OZAi90CxzMhI/e6oFmQc=',
      ),
    }),
    swCase({
      name: 'every byte 0-255 as the payload',
      secrets: [A.secret],
      messageId: A.messageId,
      timestamp: A.timestamp,
      payload: allBytes,
      signature: pinned(
        'all bytes',
        swSign(A.secret, A.messageId, A.timestamp, allBytes),
        'v1,sEcZ042G8Crqgxbybb3y0eDxQR3TcfYsk11I1XULhSI=',
      ),
      source: 'standard-webhooks/standard-webhooks#348 (known answer, recomputed here)',
    }),
    swCase({
      name: 'a lone 0xff byte',
      secrets: [A.secret],
      messageId: A.messageId,
      timestamp: A.timestamp,
      payload: loneFF,
      signature: sigFF,
    }),
    swCase({
      name: 'U+FFFD, the text a lone 0xff decodes to, signing to something else',
      secrets: [A.secret],
      messageId: A.messageId,
      timestamp: A.timestamp,
      payload: replacement,
      signature: sigFFFD,
    }),
    swCase({
      name: 'two live secrets, one entry each, in the order given',
      secrets: [A.secret, B.secret],
      ...A,
      signature: `${SIG_A} ${pinned(
        'B over A',
        swSign(B.secret, A.messageId, A.timestamp, A.payload),
        'v1,78nXHjpFP0tVJQW5D0SBwmVyyW87BV/rL6MgfM/Bw44=',
      )}`,
    }),
    swCase({
      name: 'an unknown v2 tag beside a valid entry is skipped',
      secrets: [A.secret],
      ...A,
      signature: `${IGNORED_TAG} ${SIG_A}`,
      direction: 'verify-only',
      source: `${UPSTREAM_JS_TEST}:184-190`,
    }),
    swCase({
      name: 'malformed entries beside a valid entry are skipped',
      secrets: [A.secret],
      ...A,
      signature: `garbage v1,not-base64! v1,AAAA ${SIG_A}`,
      direction: 'verify-only',
    }),
    swCase({
      name: 'a valid entry sixteenth in the list is found',
      secrets: [A.secret],
      ...A,
      signature: [...sixteenWrong.slice(1), SIG_A].join(' '),
      direction: 'verify-only',
    }),
    swCase({
      name: 'a valid entry seventeenth in the list is past the cap and not found',
      secrets: [A.secret],
      ...A,
      signature: [...sixteenWrong, SIG_A].join(' '),
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
      conformance: 'webhook-hmac-kit',
    }),
    swCase({
      name: 'a timestamp one second older than the tolerance allows',
      secrets: [A.secret],
      ...A,
      signature: SIG_A,
      now: A.timestamp + TOLERANCE + 1,
      expect: { error: 'WEBHOOK_TIMESTAMP_EXPIRED' },
    }),
    swCase({
      name: 'a timestamp one second further ahead than the tolerance allows',
      secrets: [A.secret],
      ...A,
      signature: SIG_A,
      now: A.timestamp - TOLERANCE - 1,
      expect: { error: 'WEBHOOK_TIMESTAMP_EXPIRED' },
    }),
    swCase({
      name: 'a signature made with a different key',
      secrets: [A.secret],
      ...A,
      signature: WRONG_KEY,
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
      source: `${UPSTREAM_JS_TEST}:184-190`,
    }),
    swCase({
      name: 'a message id holding dots is accepted on verify',
      secrets: [A.secret],
      messageId: dottedId,
      timestamp: A.timestamp,
      payload: A.payload,
      signature: pinned(
        'dotted id',
        swSign(A.secret, dottedId, A.timestamp, A.payload),
        'v1,3EynR8r81XExuWpB/QHsAAETyykY6G71pdXKqmT7BPQ=',
      ),
      direction: 'verify-only',
    }),
    swCase({
      name: 'a 23-byte key is accepted on verify',
      secrets: [UNPADDED_SECRET],
      messageId: 'msg_1',
      timestamp: A.timestamp,
      payload: emptyObject,
      signature: pinned(
        '23-byte key',
        swSign(UNPADDED_SECRET, 'msg_1', A.timestamp, emptyObject),
        'v1,SoADEdRRWRZ60AdbTHDnDlkpalh1ZL+g5rFkCkPtlR8=',
      ),
      direction: 'verify-only',
      source: `${UPSTREAM}:libraries/python/tests/test_webhooks.py:190-195`,
    }),
    swCase({
      name: 'a 23-byte key is refused at sign time',
      secrets: [UNPADDED_SECRET],
      messageId: 'msg_1',
      timestamp: A.timestamp,
      payload: emptyObject,
      signature: swSign(UNPADDED_SECRET, 'msg_1', A.timestamp, emptyObject),
      expect: { reject: 'sign' },
      conformance: 'webhook-hmac-kit',
    }),
  ],
};

// --- this package's v2 scheme ------------------------------------------------------------------

const V2_SECRET = 'whsec_test_secret_key_1234567890';
const V2_OTHER_SECRET = 'whsec_other_secret_key_0987654321';
const V2_TS = 1700000000;

function v2Sign(secret, timestamp, nonce, payload) {
  const mac = createHmac('sha256', Buffer.from(secret, 'utf8'));
  mac.update(Buffer.from(`v2.${timestamp}.${nonce}.`, 'utf8'));
  mac.update(payload);
  return `v2=${mac.digest('hex')}`;
}

function v2Case(fields) {
  const {
    name,
    secrets = [V2_SECRET],
    nonce,
    timestamp = V2_TS,
    payload,
    signature,
    now = timestamp,
    expect = 'valid',
    source = SELF,
  } = fields;
  const direction = directionFor(name, payload, expect, fields.direction);
  return {
    name,
    // The v2 scheme is this package's own, so every case in it is this package's policy.
    conformance: 'webhook-hmac-kit',
    ...(secrets.length === 1 ? { secret: secrets[0] } : { secrets }),
    nonce,
    timestamp,
    payload: payloadOf(payload),
    signature,
    direction,
    now,
    expect,
    source,
  };
}

/** The seven vectors in test/vectors.ts, pinned and recomputed. */
const V2_FIXTURES = [
  [
    'basic JSON',
    'nonce_abc123',
    '{"event":"payment.completed","amount":4999}',
    'e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887',
  ],
  [
    'empty payload',
    'nonce_empty001',
    '',
    '048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa',
  ],
  [
    'unicode payload',
    'nonce_unicode01',
    '{"name":"Héllo Wörld","emoji":"🚀"}',
    '51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2',
  ],
  [
    'whitespace preserving',
    'nonce_ws001',
    '{  "key"  :  "value"  }',
    '4e4333f9ba5692cabb2478849835027c1d2fef8f333c10410955d81091c43449',
  ],
  [
    'colons in payload',
    'nonce_colon001',
    '{"time":"12:30:45","url":"https://example.com"}',
    '683d5312932959699ba9c7bc12ea8ac9bddb6ab2ed9c59364435aa2cef76c991',
  ],
  [
    'dots and digits in payload',
    'nonce_dots001',
    '1700000001.nonce_x.{"v":"2.0.1"}',
    'c3d652678911bcd059a96e0bd3aa2bee700379649037718050486ad4896acd0b',
  ],
  [
    'byte payload that is not valid UTF-8',
    'nonce_bytes001',
    goBytes,
    '6bcc8aabb3021f06f7cb713985154d03ca3916082148444bd0cc75e3837cd430',
  ],
];

const v2Cases = V2_FIXTURES.map(([name, nonce, text, hex]) => {
  const payload = typeof text === 'string' ? Buffer.from(text, 'utf8') : text;
  return v2Case({
    name,
    nonce,
    payload,
    signature: pinned(name, v2Sign(V2_SECRET, V2_TS, nonce, payload), `v2=${hex}`),
  });
});

const basic = Buffer.from('{"event":"payment.completed","amount":4999}', 'utf8');
const SIG_BASIC = v2Sign(V2_SECRET, V2_TS, 'nonce_abc123', basic);

const v2 = {
  scheme: 'webhook-hmac-kit-v2',
  version: 1,
  note: NOTE,
  generated: SELF,
  tolerance: TOLERANCE,
  cases: [
    ...v2Cases,
    v2Case({
      name: 'every byte 0-255 as the payload',
      nonce: 'nonce_allbytes',
      payload: allBytes,
      signature: v2Sign(V2_SECRET, V2_TS, 'nonce_allbytes', allBytes),
    }),
    v2Case({
      name: 'two live secrets, the first one signs',
      secrets: [V2_SECRET, V2_OTHER_SECRET],
      nonce: 'nonce_abc123',
      payload: basic,
      signature: SIG_BASIC,
    }),
    v2Case({
      name: 'a digest in upper-case hex',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: `v2=${SIG_BASIC.slice(3).toUpperCase()}`,
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
    }),
    v2Case({
      name: 'a digest that is not hex',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: `v2=${'z'.repeat(64)}`,
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
    }),
    v2Case({
      name: 'a correct digest under an unsupported version',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: `v1=${SIG_BASIC.slice(3)}`,
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
    }),
    v2Case({
      name: 'a signature made with a different key',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: v2Sign(V2_OTHER_SECRET, V2_TS, 'nonce_abc123', basic),
      expect: { error: 'WEBHOOK_SIGNATURE_INVALID' },
    }),
    v2Case({
      name: 'a timestamp one second older than the tolerance allows',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: SIG_BASIC,
      now: V2_TS + TOLERANCE + 1,
      expect: { error: 'WEBHOOK_TIMESTAMP_EXPIRED' },
    }),
    v2Case({
      name: 'a timestamp one second further ahead than the tolerance allows',
      nonce: 'nonce_abc123',
      payload: basic,
      signature: SIG_BASIC,
      now: V2_TS - TOLERANCE - 1,
      expect: { error: 'WEBHOOK_TIMESTAMP_EXPIRED' },
    }),
    v2Case({
      name: 'a nonce holding a dot',
      nonce: 'nonce.dot',
      payload: basic,
      signature: v2Sign(V2_SECRET, V2_TS, 'nonce.dot', basic),
      expect: { error: 'WEBHOOK_NONCE_INVALID' },
    }),
  ],
};

mkdirSync(join(ROOT, 'vectors'), { recursive: true });
for (const [file, corpus] of [
  ['standard-webhooks.json', standardWebhooks],
  ['v2.json', v2],
]) {
  writeFileSync(join(ROOT, 'vectors', file), `${JSON.stringify(corpus, null, 2)}\n`);
}
