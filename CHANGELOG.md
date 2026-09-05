# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-05

### Breaking

- Canonical string changed from colon-delimited `v1:{timestamp}:{nonce}:{payload}` to
  dot-delimited `v2.{timestamp}.{nonce}.{payload}`, built as bytes rather than a string.
  Every digest changes. `verifyWebhook` hard-refuses any version but `v2` — there is no
  dual-accept window, so every in-flight v1 delivery fails at cutover.
- Signature header value changed from a bare 64-character hex digest to `v2=<64
  lower-case hex>`. Upper-case hex is rejected; a sender using, say, Go's `%X` must
  switch to `%x`.
- `secret` (a single string) replaced by `secrets: WebhookSecret | WebhookSecret[]` on
  `SignWebhookOptions`, `VerifyWebhookOptions` and every adapter's `AdapterOptions`. The
  old key is silently ignored and the new one is required, so a caller still passing
  `secret` now gets `secrets must not be empty`.
- `version` option removed from `signWebhook`. The library only ever emits and accepts
  `v2`; a caller still passing it is silently ignored, same as before.
- `payload` widened from `string` to `string | Uint8Array` on both option types. Passing
  anything else (an array, `null`, an object) used to be silently stringified by a
  template literal and now throws a `TypeError`.
- `nonce` must match `^[A-Za-z0-9_-]{1,64}$`, checked before any HMAC work runs. v1
  accepted any string.
- `signWebhook` now returns `Promise<SignWebhookResult>` instead of the result directly.
  Argument validation still throws synchronously — a caller's `try/catch` around a
  misconfiguration keeps working — only the HMAC step itself is deferred.
- `buildCanonicalString`'s arity changed from `(version, timestamp, nonce, payload)` to
  `(timestamp, nonce, payload)`. A v1 caller now passes a version string where a
  timestamp is expected and gets a `TypeError`.
- `buildCanonicalBytes()`'s return value, `ParsedSignature.digest`, `formatSignature()`'s
  parameter and `normalizeSecrets()`'s return value are `Uint8Array` rather than `Buffer`
  positionally. A `Buffer` still satisfies every one of these — it is a `Uint8Array`
  subclass — so this only breaks code that inspected the runtime type directly.
- Adapter status mapping collapsed to a uniform 401 for every verification failure. It
  used to be 401 for a bad signature, 400 for an expired timestamp and 409 for a
  replayed nonce; a client branching on those codes now sees only 401. The specific
  reason is available through `onError`, never on the wire — this is deliberate, so an
  unauthenticated caller cannot learn which check its forgery passed.
- Adapter response body collapsed to `{ error: 'Webhook verification failed' }` for
  every failure. The `code` field (`WEBHOOK_SIGNATURE_INVALID` and so on) is gone from
  the wire.
- An already-parsed request body (an object handed over by a JSON body parser that
  already ran) is now refused as a configuration error on all three adapters, instead
  of being stringified and verified as though it were the raw body.
- A secret list may not contain more than 16 distinct entries (`MAX_SECRETS`).
- `engines.node`: `>=18` → `>=22`. Decided by support policy — Node 20 reaches end of
  life 30 Apr 2026 — not by a vulnerability.
- `globalThis.crypto.subtle` is now required at runtime. There is no `node:crypto`
  fallback of any kind: a literal `node:crypto` import is resolved at bundle time by
  wrangler, esbuild and Metro whether or not it can actually run, so a guarded import
  would have cost every bundled build for nothing. A Node process started with
  `--no-experimental-global-webcrypto` now throws `WebCryptoUnavailableError` where it
  previously worked.

### Added

- `secrets` accepts a list, for rotation: sign with the first entry, verify against any
  entry in the list.
- `WebCryptoUnavailableError`, thrown when `globalThis.crypto.subtle` is missing. It
  deliberately does not extend `WebhookError`, so adapters answer it with 500 rather
  than 401 — a broken receiver, not a rejected signature. The message names the flag to
  drop and gives the one-line remedy.
- New public exports: `NONCE_PATTERN`, `buildCanonicalBytes`, `isValidNonce`,
  `isValidTimestamp`, `MAX_SECRETS`, `normalizeSecrets`, `SIGNATURE_PATTERN`,
  `formatSignature`, `parseSignature`, `SIGNATURE_VERSION`, and the types
  `ParsedSignature`, `WebhookPayload`, `WebhookSecret`.
- Adapters for Express, Fastify and NestJS (`webhook-hmac-kit/express`,
  `/fastify`, `/nest`), sharing header extraction, raw-body resolution and the uniform
  401 mapping.
- Duplicate (array-valued) request headers, on any of the three adapters, now answer
  400 `Duplicate header: <name>` instead of silently using the first value.
- CI job `edge-smoke`: the built package is imported and run against the seven test
  vectors on Node, Deno and Bun.

### Changed

- Header name options (`signatureHeader`, `timestampHeader`, `nonceHeader`) are now
  lower-cased before lookup. Node lower-cases incoming header keys, so a name
  configured as `'X-Webhook-Signature'` used to never match an incoming
  `x-webhook-signature` header and silently reported it as missing.
- A throwing or rejecting `nonceValidator` no longer propagates its own error. It
  becomes `WebhookNonceError` / `WEBHOOK_NONCE_INVALID`, with the original error
  attached at `.cause`.
- Timestamp header parsing tightened to `^(0|[1-9]\d*)$`. `+1700000000`, `1e9`, `0x10`
  and leading or trailing whitespace used to be accepted (`Number()` coerces all of
  them); none of them is the plain decimal the sender actually signed, so all now fail.
- The MAX_SECRETS-exceeded error message now states the limit only ("secrets must not
  contain more than 16 distinct entries"). It used to also report how many were
  supplied; the check now fires as soon as the list crosses the cap, during the dedupe
  pass, rather than after the whole list has been counted, and there is no honest count
  left to report at that point.
- Adapter `rawBody` option type widened from `Buffer | string` to `Uint8Array | string`
  on Fastify and NestJS. A `Buffer` still works.
- `formatSignature`'s parameter widened from `Buffer` to `Uint8Array`. A `Buffer` still
  works.
- Secrets are deduplicated by comparing their bytes directly instead of keying a map on
  a base64 copy of each one, so no second representation of key material is kept alive.
- `removeNodeProtocol: false` is now permanent in `tsup.config.ts`. tsup 8 defaults to
  rewriting `node:crypto` to a bare `crypto` specifier, which had silently made the
  `node:crypto` entry in `external` a no-op — the shipped bundle had been importing a
  bare Node builtin the whole time. A bare builtin does not resolve on Deno or under a
  browser-targeted bundler.
- CI matrix moved to Node 22 and 24; `actions/checkout` and `actions/setup-node` pinned
  to `@v7`. Third-party CI actions (`denoland/setup-deno`, `oven-sh/setup-bun`) are
  pinned by commit SHA rather than by their moving major-version tag.
- `@types/node` pinned to the supported Node line.

### Fixed

- **The canonical string was injective; the bytes actually signed were not.**
  `buildCanonicalString` produced a distinct string for every distinct
  (timestamp, nonce, payload) triple, but the signer and verifier UTF-8-encoded that
  string before hashing it, and UTF-8 encoding of a JS string is not injective — every
  unpaired surrogate encodes to the same three bytes as the replacement character
  `�`. Two payloads that differed only in such a code unit produced the same
  signature, and a signature made over one of them verified successfully against the
  other. The adapters made this reachable from real wire bytes: the raw request body
  was decoded to a string with `.toString('utf-8')` before it reached the signer, so
  two distinct byte sequences that happen to decode to the same string collapsed onto
  one signature before signing ever ran. The practical effect: a signature could check
  out against a payload the sender never actually sent, carrying the same nonce and
  timestamp the sender did sign — which undermines the "one nonce, one payload"
  assumption that a nonce cache is relied on for. Fixed by carrying the payload as
  bytes end to end — the canonical value is built with byte concatenation, not a
  template literal, and the raw body is now handed to the signer and verifier
  unchanged instead of being decoded first. A payload passed as a plain string is
  still UTF-8 encoded on the way in, so a normal JSON body signs and verifies exactly
  as before; this only changes behaviour for a payload that was not well-formed UTF-8
  to begin with.
- Signature parsing was lenient about trailing or malformed hex — a decoder stopped at
  the first pair it could not read and used whatever it had managed. It is now strict:
  anything other than exactly 64 lower-case hex characters after the version prefix is
  rejected outright, so a signature with junk appended or a folded duplicate header
  (`sigA, sigB`) can no longer verify.
- `buildCanonicalString` accepted anything as a payload and stringified it via a
  template literal, so `sign(['a'])`, `sign(null)` and `sign({})` produced the same
  signature as `sign('a')`, `sign('null')` and `sign('[object Object]')`. It now throws
  a `TypeError` for anything that is not a string or `Uint8Array`.
- The Fastify adapter's verification hook answered a failure with
  `reply.code(...).send(...)` but did not return the reply, so Fastify did not learn
  the response had already gone out and could continue into the route handler.
- The NestJS guard's raw-body configuration error escaped its `try` block entirely and
  surfaced as a bare `Error` instead of the guard's own exception; it is now caught and
  mapped the same way as every other failure.
- Express: a synchronous throw from the downstream route handler could land in the
  webhook middleware's own error handler, misreporting an unrelated error as a
  verification failure and firing `onError` for it. `.then(onSuccess, onFailure)`
  replaces `.then(onSuccess).catch(onFailure)`.
- `resolveRawBody` refused a plain `Uint8Array` request body and reported it as an
  already-parsed body, even though the core library accepts a bare `Uint8Array`
  payload. It now accepts any `Uint8Array`, not only the Node `Buffer` subclass of it.
- Secrets are now capped and deduplicated before every request pays for an HMAC per
  entry; a misconfigured list of hundreds of copies of one secret used to cost one HMAC
  per copy.

## [1.0.0] - 2026-02-01

### Added

- `signWebhook()` — synchronous HMAC-SHA256 signing over a canonical string
- `verifyWebhook()` — async verification with timestamp, signature, and nonce checks
- `buildCanonicalString()` — deterministic canonical string builder (`v1:{timestamp}:{nonce}:{payload}`)
- Typed error classes: `WebhookSignatureError`, `WebhookTimestampError`, `WebhookNonceError`
- Input validation for secret, timestamp, and tolerance parameters
- Constant-time signature comparison via `crypto.timingSafeEqual`
- Configurable timestamp tolerance (default: 300 seconds)
- Optional `nonceValidator` callback for replay protection
- Dual module format: ESM + CJS with full TypeScript declarations
- 5 published test vectors for cross-language verification
