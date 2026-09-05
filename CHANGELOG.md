# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-09-05

### Added

- Standard Webhooks support, as a separate scheme rather than a mode of this one:
  `signStandardWebhooks`, `verifyStandardWebhooks` and `parseStandardWebhooksSecret`,
  exported from the package entry point with `StandardWebhooksSecret`,
  `StandardWebhooksHeaders` and the two option types. Zero new dependencies. Nothing
  about the `v2` wire format changes, and the adapters are untouched: there is no
  `standardWebhooks` flag on them, because one option carrying both secret encodings
  would make the same configured string a different key depending on a boolean, and
  their scheme has no field that can carry replay protection.
- `MAX_SIGNATURE_ENTRIES`, the number of `webhook-signature` entries a verify will
  weigh. Equal to `MAX_SECRETS`, and exported for the same reason: it changes what a
  verify accepts, so it belongs in the API rather than only in the README.
- `toBase64` and `fromBase64` in `src/bytes.ts`, internal. Strict about the alphabet
  and the group length where the platform decoders are not, deliberately lenient about
  the bits below the last whole byte, because the unpadded secrets in the upstream
  Standard Webhooks fixtures set them.

### Fixed

- All four of `signWebhook`, `verifyWebhook`, `signStandardWebhooks` and
  `verifyStandardWebhooks` now refuse to proceed when `subtle.sign` returns a buffer
  that is not 32 bytes. On the verify side an empty return made every blinded value the
  same empty run, the constant-time fold found no difference between them, and a forged
  signature verified. On the sign side there was no comparison to fool: a short MAC
  shipped, as `v2=` with eight hex characters or a `v1,` entry decoding to nothing.
  Present since 2.0.0 and reachable only on a broken or tampered runtime, since nothing
  an attacker sends can change what Web Crypto returns. It now throws a plain `Error`,
  not a `WebhookError`: the machine is broken rather than the request being wrong, so
  adapters answer 500 and not 401.

### Changed

- `verifyStandardWebhooks` weighs at most 16 signature entries, the same cap that
  bounds the secret list. The entry count arrives from the network and each entry was
  compared against every configured secret, so a 16 KiB header of correct-length junk
  bought 10800 `subtle.sign` calls and 110 ms of CPU per unauthenticated request
  against a 16-key rotation. A conforming sender emits one entry per live key, so
  nothing legitimate reaches the cap; a valid signature beyond it is not found.
- Blinding is now done once per request rather than once per comparison, so comparing
  `s` secrets against `e` entries costs `s + e` signatures instead of `2 × s × e`. The
  same 16-key, 337-entry request now costs 48 `subtle.sign` calls and 0.6 ms.
  `verifyWebhook` is unchanged: it carries one presented signature, so it has no
  quadratic term to remove.

### Known limitations of the Standard Webhooks scheme

Both are properties of that specification, not of this implementation, and both are
pinned by tests rather than worked around, because working around either would mean
emitting signatures no conforming receiver accepts.

- **`webhook-id` is not a trust boundary.** The signed value is
  `{id}.{timestamp}.{payload}` with nothing constraining the id, so an id containing a
  dot and a run of digits re-splits into a different, equally valid message carrying
  the same signature. `verifyStandardWebhooks` therefore offers no replay hook keyed on
  it. The `v2` scheme's nonce is dot-free by construction and does not have this
  problem.
- **The two schemes must never share key material.** `v2.{ts}.{nonce}.{payload}` is
  byte-identical to a Standard Webhooks message whose id is the literal `v2` and whose
  payload is `{nonce}.{payload}`, so one key used for both lets a signature minted
  under either be presented as valid under the other. Generate a separate secret.

### Interop

Reproduces the de-facto vector shared by six reference implementations (the JavaScript,
Go, Python, Ruby, PHP and C# suites all pin the same one) and the Rust crate's own
vector, signing and verifying, byte for byte. There is no official conformance suite.
Not covered: `svix-*` alias headers, the asymmetric `v1a` tag, JSON parsing of the
payload, and bodies that are not well-formed UTF-8, where the reference libraries
disagree with one another so no single behaviour is conformant.

## [2.0.0] - 2026-09-05

The real baseline for this entry is npm's published 1.0.0 (02 Feb 2026), which shipped
`dist/index.*` only and had no adapters. The Express, Fastify and NestJS adapters were
merged to git main afterwards without a version bump and were never published, so they
are new to anyone installing from npm, not a change to something npm ever shipped.

### Breaking

- Canonical string changed from colon-delimited `v1:{timestamp}:{nonce}:{payload}` to
  dot-delimited `v2.{timestamp}.{nonce}.{payload}`, built as bytes rather than a string.
  Every digest changes. `verifyWebhook` hard-refuses any version but `v2`: there is no
  dual-accept window, so every in-flight v1 delivery fails at cutover.
- Signature header value changed from a bare 64-character hex digest to `v2=<64
  lower-case hex>`. Upper-case hex is rejected; a sender using, say, Go's `%X` must
  switch to `%x`.
- `secret` (a single string) replaced by `secrets: WebhookSecret | WebhookSecret[]` on
  `SignWebhookOptions` and `VerifyWebhookOptions`. A caller who still passes only
  `secret` gets `each secret must be a non-empty string or byte array`, because
  `secrets` is then `undefined` and the check sees one unusable entry, not zero.
- `version` option removed from `signWebhook`. In 1.0.0 that option fed straight into
  the canonical string, so a caller who set it got a genuinely different signing
  digest, one `verifyWebhook` could never check because the verify side hard-coded
  `v1` regardless of what was signed with. In 2.0.0 the option is gone: passing it is
  ignored, and the library always emits and accepts `v2`.
- `payload` widened from `string` to `string | Uint8Array` on both option types.
  Passing anything else (an array, `null`, an object) used to be silently stringified
  by a template literal and now throws a `TypeError`.
- `nonce` must match `^[A-Za-z0-9_-]{1,64}$`, checked before any HMAC work runs. v1
  accepted any string.
- `signWebhook` now returns `Promise<SignWebhookResult>` instead of the result
  directly. Argument validation still throws synchronously, so a caller's `try/catch`
  around a misconfiguration keeps working; only the HMAC step itself is deferred.
- `buildCanonicalString`, a public export in 1.0.0, is no longer exported from the
  package. Use `buildCanonicalBytes` instead, and never hash the string form: hashing
  it re-introduces the exact UTF-8 encoding gap this release closes, see Fixed below.
- `DEFAULT_VERSION` is no longer exported.
- Core timestamp validation tightened from `Number.isFinite` to a non-negative safe
  integer. A float or an out-of-range value that 1.0.0 accepted, and silently folded
  into the canonical string, is now refused before any HMAC work: `signWebhook`
  throws a `TypeError`, `verifyWebhook` throws `WebhookTimestampError` /
  `WEBHOOK_TIMESTAMP_INVALID`.
- `signWebhook` now validates `timestamp` and `nonce` before signing. 1.0.0 validated
  only the secret, so a malformed timestamp or nonce used to sign successfully.
- `WebhookErrorCode` gained two members, `WEBHOOK_TIMESTAMP_INVALID` and
  `WEBHOOK_NONCE_INVALID`, and the `WebhookTimestampError` / `WebhookNonceError`
  constructors gained `code` and `ErrorOptions` parameters. A consumer with an
  exhaustive `switch` over the 1.0.0 three-member union now has an unhandled case.
- Verification is asynchronous end to end and costs 3 `subtle.sign` calls plus 2
  `subtle.importKey` calls per configured secret, where 1.0.0 did one synchronous
  `createHmac` call and one `timingSafeEqual` call.
- `engines.node`: `>=18` → `>=22`. Decided by support policy, Node 20 reaches end of
  life 30 Apr 2026, not by a vulnerability.
- `globalThis.crypto.subtle` is now required at runtime. There is no `node:crypto`
  fallback of any kind: a literal `node:crypto` import is resolved at bundle time by
  wrangler, esbuild and Metro whether or not it can actually run, so a guarded import
  would have cost every bundled build for nothing. A Node process started with
  `--no-experimental-global-webcrypto` now throws `WebCryptoUnavailableError` where it
  previously worked.

### Added

- `secrets` accepts a list, for rotation: sign with the first entry, verify against any
  entry in the list. A list may hold at most 16 distinct entries (`MAX_SECRETS`).
- `WebCryptoUnavailableError`, thrown when `globalThis.crypto.subtle` is missing. It
  deliberately does not extend `WebhookError`, so adapters answer it with 500 rather
  than 401, a broken receiver, not a rejected signature. The message names the flag to
  drop and gives the remedy.
- New public exports: `NONCE_PATTERN`, `buildCanonicalBytes`, `isValidNonce`,
  `isValidTimestamp`, `MAX_SECRETS`, `normalizeSecrets`, `SIGNATURE_PATTERN`,
  `formatSignature`, `parseSignature`, `SIGNATURE_VERSION`, and the types
  `ParsedSignature`, `WebhookPayload`, `WebhookSecret`. The byte-level ones among
  these (`buildCanonicalBytes`, `ParsedSignature.digest`, `formatSignature`,
  `normalizeSecrets`) use `Uint8Array` throughout; a `Buffer` still satisfies all of
  it, since it is a `Uint8Array` subclass.
- Adapters for Express, Fastify and NestJS (`webhook-hmac-kit/express`, `/fastify`,
  `/nest`), new to npm as noted above. Design notes that apply to all three:
  - every verification failure maps to the same 401 with the same body
    (`{ error: 'Webhook verification failed' }`); the specific reason is available
    only through `onError`, so an unauthenticated caller cannot learn which check its
    forgery passed
  - an already-parsed request body (an object handed over by a JSON body parser that
    already ran) is refused as a configuration error, instead of being stringified
    and verified as though it were the raw body
  - duplicate (array-valued) request headers answer 400 `Duplicate header: <name>`
    instead of silently using the first value
  - header name options (`signatureHeader`, `timestampHeader`, `nonceHeader`) are
    lower-cased before lookup, since Node lower-cases incoming header keys

  Bugs found in the adapters and fixed before any of it reached npm:
  - the Fastify verification hook didn't return the reply on a failure, so Fastify
    could carry on into the route handler after a response had already gone out
  - the Nest guard's raw-body configuration error escaped its `try` block and
    surfaced as a bare `Error`, instead of being caught and mapped like every other
    failure
  - a synchronous throw from the downstream Express handler could land in the
    webhook middleware's own error handler, misreporting an unrelated error as a
    verification failure
  - `resolveRawBody` refused a plain `Uint8Array` request body and reported it as
    an already-parsed one, even though the core library accepts a bare `Uint8Array`
    payload
  - an `onError` callback that itself threw could leave a request with no response
    at all
- CI job `edge-smoke`: the built package is imported and run against the seven test
  vectors on Node, Deno and Bun.

### Changed

- A throwing or rejecting `nonceValidator` no longer propagates its own error. It
  becomes `WebhookNonceError` / `WEBHOOK_NONCE_INVALID`, with the original error
  attached at `.cause`.
- Timestamp header parsing tightened to `^(0|[1-9]\d*)$`. `+1700000000`, `1e9`, `0x10`
  and leading or trailing whitespace used to be accepted (`Number()` coerces all of
  them); none of them is the plain decimal the sender actually signed, so all now fail.
- The MAX_SECRETS-exceeded error message now states the limit only ("secrets must not
  contain more than 16 distinct entries"). It used to also report how many were
  supplied; the check now fires as soon as the list crosses the cap, during the dedupe
  pass, rather than after the whole list has been counted, and there is no honest
  count left to report at that point.
- Secrets are deduplicated by comparing their bytes directly instead of keying a map
  on a base64 copy of each one, so no second representation of key material is kept
  alive.
- `removeNodeProtocol: false` is now permanent in `tsup.config.ts`. tsup 8 defaults to
  rewriting `node:crypto` to a bare `crypto` specifier, which had silently made the
  `node:crypto` entry in `external` a no-op: the shipped bundle had been importing a
  bare Node builtin the whole time. A bare builtin does not resolve on Deno or under a
  browser-targeted bundler.
- CI matrix moved to Node 22 and 24; `actions/checkout` and `actions/setup-node`
  pinned to `@v7`. Third-party CI actions (`denoland/setup-deno`, `oven-sh/setup-bun`)
  are pinned by commit SHA rather than by their moving major-version tag.
- `@types/node` pinned to the supported Node line.

### Fixed

- **The v1 canonical string could be re-split into a different nonce and payload, and
  the forged split replayed straight past a correct nonce cache.** The old format
  joined `{version}:{timestamp}:{nonce}:{payload}` on a colon that neither the nonce
  nor the payload was ever constrained against, so a payload containing a colon let
  the same bytes on the wire parse as more than one (nonce, payload) split, each one
  byte-identical to what was actually signed, so each one verified. The nonce is the
  value a replay cache keys on, so an attacker who had seen one delivery could present
  it again with the split point moved a colon over: every variant reads as a fresh
  nonce to the cache, so a cache that correctly rejects the honest replay waves the
  forged ones through anyway. The parsed payload was also silently truncated by the
  same re-split: for JSON that usually fails closed (most JSON contains a colon), but
  a form-encoded, CSV or plain-text payload can truncate without any error at all.
  Fixed by moving the delimiter to a dot and constraining the nonce to
  `^[A-Za-z0-9_-]{1,64}$`, dot-free, so it can never be mistaken for the boundary,
  which makes the split unambiguous rather than merely unlikely to collide.
- **The canonical string was injective; the bytes actually signed were not.**
  `buildCanonicalString` produced a distinct string for every distinct
  (timestamp, nonce, payload) triple, but the signer and verifier UTF-8-encoded that
  string before hashing it, and UTF-8 encoding of a JS string is not injective: every
  unpaired surrogate encodes to the same three bytes as the replacement character
  `�`. Two payloads that differed only in such a code unit produced the same
  signature, and a signature made over one of them verified successfully against the
  other. The adapters made this reachable from real wire bytes: the raw request body
  was decoded to a string with `.toString('utf-8')` before it reached the signer, so
  two distinct byte sequences that happen to decode to the same string collapsed onto
  one signature before signing ever ran. The practical effect: a signature could
  check out against a payload the sender never actually sent, carrying the same nonce
  and timestamp the sender did sign, which undermines the "one nonce, one payload"
  assumption that a nonce cache is relied on for. Fixed by carrying the payload as
  bytes end to end: the canonical value is built with byte concatenation, not a
  template literal, and the raw body is now handed to the signer and verifier
  unchanged instead of being decoded first. A payload passed as a plain string is
  still UTF-8 encoded on the way in, so a normal JSON body signs and verifies exactly
  as before; this only changes behaviour for a payload that was not well-formed UTF-8
  to begin with.
- Signature parsing was lenient about trailing or malformed hex: a decoder stopped at
  the first pair it could not read and used whatever it had managed. It is now strict:
  anything other than exactly 64 lower-case hex characters after the version prefix is
  rejected outright, so a signature with junk appended or a folded duplicate header
  (`sigA, sigB`) can no longer verify.
- `buildCanonicalString` accepted anything as a payload and stringified it via a
  template literal, so `sign(['a'])`, `sign(null)` and `sign({})` produced the same
  signature as `sign('a')`, `sign('null')` and `sign('[object Object]')`. It now throws
  a `TypeError` for anything that is not a string or `Uint8Array`.
- Secrets are now capped and deduplicated before every request pays for an HMAC per
  entry; a misconfigured list of hundreds of copies of one secret used to cost one HMAC
  per copy.

## [1.0.0] - 2026-02-01

### Added

- `signWebhook()`: synchronous HMAC-SHA256 signing over a canonical string
- `verifyWebhook()`: async verification with timestamp, signature, and nonce checks
- `buildCanonicalString()`: deterministic canonical string builder (`v1:{timestamp}:{nonce}:{payload}`)
- Typed error classes: `WebhookSignatureError`, `WebhookTimestampError`, `WebhookNonceError`
- Input validation for secret, timestamp, and tolerance parameters
- Constant-time signature comparison via `crypto.timingSafeEqual`
- Configurable timestamp tolerance (default: 300 seconds)
- Optional `nonceValidator` callback for replay protection
- Dual module format: ESM + CJS with full TypeScript declarations
- 5 published test vectors for cross-language verification
