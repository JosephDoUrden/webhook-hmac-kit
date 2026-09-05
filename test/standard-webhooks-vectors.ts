/**
 * Standard Webhooks vectors, copied verbatim from the reference implementations.
 *
 * There is no official conformance suite for Standard Webhooks: no shared fixture file, no
 * cross-language vector JSON. What exists is one vector pasted into the JavaScript, Go, Python,
 * Ruby, PHP and C# test files, and a second one that only the Rust crate carries. Those are what
 * an interop claim can honestly rest on, so they are pinned here with the exact source they were
 * taken from rather than regenerated.
 *
 * Every value below was also reproduced independently before being committed, with
 *
 *   node -e "const c=require('crypto');
 *   const key=Buffer.from('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw','base64');
 *   const signed='msg_p5jXN8AQM9LWM0D4loKWxJek.1614265330.{\"test\": 2432232314}';
 *   console.log('v1,'+c.createHmac('sha256',key).update(signed).digest('base64'));"
 *
 * so a failure here means our implementation moved, not that the fixture was mistyped.
 *
 * Provenance is `repo@sha:path:lines`, against
 * standard-webhooks/standard-webhooks@7537d2a2d3d52d8f2e0ecd12527af4a9307fd81b (main as at
 * 05 Sep 2026; that commit is dated 31 Aug 2026). Spec Apache-2.0, libraries MIT (c) 2023 Svix.
 * The wire grammar and the vectors are facts about a published specification; no upstream code is
 * copied into this package.
 */

export interface StandardWebhooksVector {
  name: string;
  /** As the upstream fixture spells it, `whsec_` prefix included. */
  secret: string;
  messageId: string;
  timestamp: number;
  payload: string;
  /** The whole `webhook-signature` value: one entry, tag included. */
  signature: string;
}

/**
 * The six-language de-facto vector.
 *
 * standard-webhooks/standard-webhooks@7537d2a:libraries/javascript/src/webhook.test.ts:206-211
 * and the same constants at
 *   libraries/go/webhook_test.go, libraries/python/tests/test_webhooks.py:213-220,
 *   libraries/ruby/spec/webhook_spec.rb, libraries/php/tests/WebhookTest.php,
 *   libraries/csharp/StandardWebhooks.Tests/WebhookTest.cs
 *
 * The space after the colon in the payload is part of the vector. Removing it changes the digest.
 */
export const VECTOR_A: StandardWebhooksVector = {
  name: 'the six-language de-facto vector',
  secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  messageId: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
  timestamp: 1614265330,
  payload: '{"test": 2432232314}',
  signature: 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
};

/**
 * The Rust crate's own vector. Its secret contains a '+', which is what makes it worth keeping:
 * a URL-safe decoder would read that character as something else and produce a different key.
 *
 * standard-webhooks/standard-webhooks@7537d2a:libraries/rust/src/lib.rs:190-201
 */
export const VECTOR_B: StandardWebhooksVector = {
  name: "the Rust crate's vector",
  secret: 'whsec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD',
  messageId: 'msg_27UH4WbU6Z5A5EzD8u03UvzRbpk',
  timestamp: 1649367553,
  payload: '{"email":"test@example.com","username":"test_user"}',
  signature: 'v1,tZ1I4/hDygAJgO5TYxiSd6Sd0kDW6hPenDe+bTa3Kkw=',
};

/**
 * The wrong-key signature the JavaScript and Go suites reuse for their negative paths, and the
 * `v2,` spelling of it that their multi-signature tests require a receiver to SKIP rather than
 * reject. Our own scheme uses a different header and a different separator, so this `v2` tag and
 * this package's `v2=` signatures cannot be confused for one another.
 *
 * standard-webhooks/standard-webhooks@7537d2a:libraries/javascript/src/webhook.test.ts:184-190
 */
export const WRONG_KEY_SIGNATURE = 'v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=';
export const IGNORED_VERSION_SIGNATURE = 'v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=';

/**
 * The 31-character secret whose test asserts an unpadded `whsec_` value works. It decodes to 23
 * bytes, one under the 24 the spec states as its minimum, so it is a verify-path fixture: no
 * reference library enforces the range, and refusing a key on receive that a Python sender is
 * already signing with would break a live integration to make a point.
 *
 * It also sets the two bits below its last whole byte, which is why fromBase64 does not insist
 * those be zero.
 *
 * standard-webhooks/standard-webhooks@7537d2a:libraries/python/tests/test_webhooks.py:190-195
 */
export const UNPADDED_SECRET = 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS';

/**
 * A byte payload that is not valid UTF-8, signed the way Go signs it: over the exact bytes.
 *
 * Go's `fmt.Sprintf("%s.%d.%s", msgId, ts, payload)` copies a []byte verbatim, so Go is the only
 * reference implementation that is byte-transparent. JavaScript and Python decode the body to a
 * string first and mangle 0xff into U+FFFD; Rust refuses it outright. This fixture is what a Go
 * sender puts on the wire, and our verify path has to accept it.
 *
 * Generated with the same node one-liner as the vectors above, over
 * Buffer.concat([Buffer.from('msg_bytes.1614265330.'), Buffer.from([0x7b, 0xff, 0x7d])]).
 */
export const GO_BYTE_PAYLOAD = {
  secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
  messageId: 'msg_bytes',
  timestamp: 1614265330,
  payload: Uint8Array.from([0x7b, 0xff, 0x7d]),
  signature: 'v1,D7UbbA/lAk3cw4K7TmhocB2OZAi90CxzMhI/e6oFmQc=',
};

/**
 * Three signatures with no upstream source, computed here so the tests that need them do not have
 * to compute them with the code under test. Each one was produced by the node one-liner at the top
 * of this file, over the key and signed value named in its comment.
 */

/** VECTOR_B's key over VECTOR_A's message. Pins the order of a two-secret signature header. */
export const VECTOR_B_OVER_VECTOR_A_SIGNATURE = 'v1,78nXHjpFP0tVJQW5D0SBwmVyyW87BV/rL6MgfM/Bw44=';

/**
 * VECTOR_A's key over `msg.with.dots.1614265330.{"test": 2432232314}`.
 *
 * A message id holding dots is legal for Standard Webhooks and no reference library refuses one,
 * so a receiver has to accept it. Our signer will not emit one, which is why this fixture cannot
 * be produced by calling signStandardWebhooks.
 */
export const DOTTED_ID_SIGNATURE = 'v1,3EynR8r81XExuWpB/QHsAAETyykY6G71pdXKqmT7BPQ=';

/**
 * The 23-byte UNPADDED_SECRET over `msg_1.1614265330.{}`.
 *
 * Same reason: our signer refuses a key below the spec's 24-byte floor, so the only way to hold a
 * signature made with one is to pin it.
 */
export const UNPADDED_SECRET_SIGNATURE = 'v1,SoADEdRRWRZ60AdbTHDnDlkpalh1ZL+g5rFkCkPtlR8=';
