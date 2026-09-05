# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`webhook-hmac-kit` signs and verifies webhook requests with HMAC-SHA256: timestamp
validation, nonce-based replay protection, secret rotation, and adapters for Express,
Fastify and NestJS. See `PRD.md` for the original product requirements — parts of it
predate 2.0.0 (adapters, rotation, Web Crypto); check `CHANGELOG.md` before trusting a
detail there over the code.

## Tech Stack

- TypeScript, running on Node >=22, Cloudflare Workers, Deno and Bun alike
- `globalThis.crypto.subtle` (Web Crypto) only — no `node:crypto`, guarded or otherwise
- Dual module format: ESM + CJS, fully tree-shakeable
- License: MIT

## Build & Development Commands

```bash
npm run build        # Build ESM + CJS + type declarations (tsup)
npm run typecheck    # Type-check without emitting (tsc --noEmit)
npm run test         # Run tests once (vitest run)
npm run test:watch   # Run tests in watch mode (vitest)
npm run test:coverage # Run tests with v8 coverage
npm run lint         # Lint and format check (biome check .)
npm run lint:fix     # Auto-fix lint and format issues (biome check --write .)
npm run format       # Format all files (biome format --write .)
```

## Architecture & Design Constraints

### Canonical format

```
v2.{timestamp}.{nonce}.{payload}
```

Built as bytes (`src/canonical.ts`, `buildCanonicalBytes`), not a template-literal
string. The nonce grammar (`^[A-Za-z0-9_-]{1,64}$`) is dot-free by design, because the
dot is the field delimiter — a nonce that could contain one would make the encoding
ambiguous. `buildCanonicalString` (the readable, string-only form) exists for test
vectors and display only; it is not exported from `src/index.ts` and must never be fed
to an HMAC — that string is UTF-8-encoded on the way in, and UTF-8 encoding of a JS
string is not injective (every unpaired surrogate collapses onto the same three bytes
as `U+FFFD`). That gap — two different payloads sharing one signature — was the
headline bug fixed for 2.0.0; do not reintroduce a code path that decodes the raw body
to a string before it reaches the signer or verifier.

### No `node:` imports, guarded or not

`src/` has zero `node:` specifiers. A literal `node:crypto` import is resolved at
bundle time by wrangler, esbuild and Metro whether or not the surrounding code can
actually run — a `try/catch` around a dynamic import buys nothing and costs every
bundled build. `src/crypto.ts` is the only module that touches `globalThis.crypto`; if
Web Crypto is missing it throws `WebCryptoUnavailableError`, which carries the flag to
drop and the manual-install remedy in its message. Do not add a `node:crypto` fallback
back in, guarded or not — this was a deliberate, reconsidered decision (see the Web
Crypto migration plan in the project history), not an oversight.

### `signWebhook` is a plain function, not `async`

It validates its arguments synchronously and returns `subtle.sign(...).then(...)`
rather than being declared `async`. Marking it `async` would turn every argument
mistake — an empty secret list, a malformed nonce, a payload that is neither a string
nor a `Uint8Array` — into a rejected promise instead of a synchronous throw, silently
breaking a caller's `try/catch` around a misconfiguration. Keep validation synchronous
and only the HMAC step deferred.

### The await-guard

`test/await-guard.test.ts` statically scans the async property-test files and fails if
any `fc.assert(fc.asyncProperty(...))` call is missing its `await`. A forgotten
`await` makes vitest report the property as passed while it verified nothing. If you
add or edit an async property test, run this test and make sure it still catches a
deliberately removed `await`.

### The migration oracle

`test/migration.oracle.test.ts` pins the externally observable behaviour that must
survive any internal change: error classes and codes, rejection (not `{valid: false}`)
on every failure, `WebhookNonceError.cause`, check order (timestamp, nonce grammar,
signature syntax and version, HMAC, replay), and the adapter 401-plus-body shape.
Extend this file before changing `signer.ts` or `verifier.ts` internals, not after.

### `test/vectors.ts` is the wire contract

Seven fixed `(secret, timestamp, nonce, payload, signature)` tuples, one of them a
byte payload that is not valid UTF-8. Anything that changes one of these digests is a
breaking change to the wire format — it needs a major version bump and a CHANGELOG
entry naming the collision, not a quiet fix. The file's header comment has the
one-liners to regenerate a digest by hand if you ever need to check one independently.

### Critical Security Rules

- **Raw body, as bytes, end to end.** `resolveRawBody` in `src/adapters/shared.ts`
  must hand back the exact bytes (or the exact string) unchanged — never decode to a
  string with `.toString('utf-8')` and discard the original bytes. That decode was the
  2.0.0 headline bug: it let two distinct raw bodies collapse onto one signature.
- **Constant-time comparison** is `blindedEqual` in `src/crypto.ts` (a Double-HMAC
  blind on Web Crypto). Never `===` on hex strings, never a bare byte loop as the
  primary compare, never a preference branch for a runtime-specific
  `crypto.subtle.timingSafeEqual`. See `SECURITY.md` for why.
- **Nonce-based replay protection**: the library owns no storage. Consumers supply
  `nonceValidator`, called only after the signature has already checked out.

### Core API Surface

- `signWebhook({ secrets, payload, timestamp, nonce })` → `Promise<{ signature }>`
- `verifyWebhook({ secrets, payload, signature, timestamp, nonce, tolerance?, nonceValidator? })` → `Promise<{ valid: true }>`
- Adapters at `./express`, `./fastify`, `./nest` — `webhookVerifier`, `webhookPlugin`,
  `WebhookGuard` + `WebhookModule` respectively — all built on the shared helpers in
  `src/adapters/shared.ts` (header extraction, raw-body resolution, the uniform 401
  mapping). The Nest guard throws its own local exception class, not
  `@nestjs/common`'s `HttpException` — this library has no dependency on
  `@nestjs/common` — so a global Nest exception filter will render it as a 500 unless
  the caller maps it. Keep that behaviour documented rather than "fixing" it by adding
  a dependency.

### Error States

`WebhookSignatureError`, `WebhookTimestampError` and `WebhookNonceError` all extend
`WebhookError`; adapters map every one of them to the same 401 with the same body, on
purpose — a distinct status per failure type would tell an unauthenticated caller how
far its forgery got. The specific reason is available only through `onError`.
`WebCryptoUnavailableError` deliberately does not extend `WebhookError`: it means the
receiver is broken, not that a request failed to verify, so it maps to 500.

### Scope Boundaries

- No encryption — signing only, not payload confidentiality.
- No built-in persistence layer for nonces.
- Express, Fastify and NestJS adapters exist and ship under `./express`, `./fastify`,
  `./nest` — they are no longer future work.
- Standard Webhooks compatibility and any non-injectivity work on top of it are future
  work (targeted 2.1.0), not this version.
