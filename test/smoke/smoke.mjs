/**
 * Runs the built package on whichever runtime is executing this file.
 *
 * A plain script, not a vitest suite: vitest only runs on Node, and the whole point of the Web
 * Crypto migration is the runtimes it does not run on. node:assert/strict is the one testing API
 * that Node, Deno and Bun all have, so one file covers all three with no flags and no config.
 *
 *   node test/smoke/smoke.mjs
 *   deno run test/smoke/smoke.mjs
 *   bun  test/smoke/smoke.mjs
 *
 * It imports from dist/, so `npm run build` has to have run. That is deliberate — the thing worth
 * smoking is the artefact that gets published, including whatever tsup did to the specifiers on
 * the way out.
 */

import assert from 'node:assert/strict';
import { signWebhook, verifyWebhook } from '../../dist/index.js';

const SECRET = 'whsec_test_secret_key_1234567890';
const TIMESTAMP = 1700000000;

// The vectors are old enough that every one of them is outside the default replay window, so the
// tolerance is opened up rather than the clock being faked — there is no shared way to fake a clock
// across three runtimes.
const TOLERANCE = Number.MAX_SAFE_INTEGER;

const vectors = [
  {
    name: 'basic JSON',
    payload: '{"event":"payment.completed","amount":4999}',
    nonce: 'nonce_abc123',
    signature: 'v2=e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887',
  },
  {
    name: 'empty payload',
    payload: '',
    nonce: 'nonce_empty001',
    signature: 'v2=048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa',
  },
  {
    name: 'unicode payload',
    payload: '{"name":"Héllo Wörld","emoji":"🚀"}',
    nonce: 'nonce_unicode01',
    signature: 'v2=51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2',
  },
  {
    name: 'whitespace preserving',
    payload: '{  "key"  :  "value"  }',
    nonce: 'nonce_ws001',
    signature: 'v2=4e4333f9ba5692cabb2478849835027c1d2fef8f333c10410955d81091c43449',
  },
  {
    name: 'colons in payload',
    payload: '{"time":"12:30:45","url":"https://example.com"}',
    nonce: 'nonce_colon001',
    signature: 'v2=683d5312932959699ba9c7bc12ea8ac9bddb6ab2ed9c59364435aa2cef76c991',
  },
  {
    name: 'dots and digits in payload',
    payload: '1700000001.nonce_x.{"v":"2.0.1"}',
    nonce: 'nonce_dots001',
    signature: 'v2=c3d652678911bcd059a96e0bd3aa2bee700379649037718050486ad4896acd0b',
  },
  {
    // 0xff is not valid UTF-8. If a runtime decoded this body to text on the way in, it would sign
    // to the same digest as 0xfe and the two bodies would share a signature.
    name: 'byte payload that is not valid UTF-8',
    payload: Uint8Array.from([0x7b, 0xff, 0x7d]),
    nonce: 'nonce_bytes001',
    signature: 'v2=6bcc8aabb3021f06f7cb713985154d03ca3916082148444bd0cc75e3837cd430',
  },
];

for (const vector of vectors) {
  const { signature } = await signWebhook({
    secrets: SECRET,
    payload: vector.payload,
    timestamp: TIMESTAMP,
    nonce: vector.nonce,
  });
  assert.equal(signature, vector.signature, `sign: ${vector.name}`);

  const result = await verifyWebhook({
    secrets: SECRET,
    payload: vector.payload,
    signature: vector.signature,
    timestamp: TIMESTAMP,
    nonce: vector.nonce,
    tolerance: TOLERANCE,
  });
  assert.deepEqual(result, { valid: true }, `verify: ${vector.name}`);
}

// A forgery is a rejection, not a falsy result.
await assert.rejects(
  verifyWebhook({
    secrets: SECRET,
    payload: vectors[0].payload,
    signature: `v2=${'0'.repeat(64)}`,
    timestamp: TIMESTAMP,
    nonce: vectors[0].nonce,
    tolerance: TOLERANCE,
  }),
  (error) => error.code === 'WEBHOOK_SIGNATURE_INVALID',
);

// Rotation: a signature made with the retiring secret still verifies, and every candidate is tried.
const rotation = [SECRET, 'whsec_old_secret_key_0000000000'];
const { signature: oldSignature } = await signWebhook({
  secrets: rotation[1],
  payload: 'rotate',
  timestamp: TIMESTAMP,
  nonce: 'rotation_nonce_1',
});
assert.deepEqual(
  await verifyWebhook({
    secrets: rotation,
    payload: 'rotate',
    signature: oldSignature,
    timestamp: TIMESTAMP,
    nonce: 'rotation_nonce_1',
    tolerance: TOLERANCE,
  }),
  { valid: true },
);

// Argument validation still throws where the caller can catch it, on every runtime.
assert.throws(
  () => signWebhook({ secrets: '', payload: 'x', timestamp: TIMESTAMP, nonce: 'n' }),
  /each secret must be a non-empty string or byte array/,
);

const runtime =
  typeof Deno !== 'undefined'
    ? `Deno ${Deno.version.deno}`
    : typeof Bun !== 'undefined'
      ? `Bun ${Bun.version}`
      : `Node ${globalThis.process.versions.node}`;

console.log(`smoke ok on ${runtime}: ${vectors.length} vectors signed and verified`);
