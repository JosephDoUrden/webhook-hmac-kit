# webhook-hmac-kit

[![npm version](https://img.shields.io/npm/v/webhook-hmac-kit)](https://www.npmjs.com/package/webhook-hmac-kit)
[![npm downloads](https://img.shields.io/npm/dw/webhook-hmac-kit)](https://www.npmjs.com/package/webhook-hmac-kit)
[![license](https://img.shields.io/npm/l/webhook-hmac-kit)](https://github.com/JosephDoUrden/webhook-hmac-kit/blob/main/LICENSE)

Sign and verify webhook requests with HMAC-SHA256: timestamp validation, nonce-based
replay protection, secret rotation, and adapters for Express, Fastify and NestJS.

![demo](docs/demo.gif)

Runs on Web Crypto only, so it works the same way on Node, Cloudflare Workers, Deno and
Bun with no bundler configuration and no runtime branch.

**2.0.0 is a breaking release.** The wire format changed. See [CHANGELOG.md](CHANGELOG.md)
before upgrading in place: a v1 signature is refused outright, with no dual-accept window.

## Install

```bash
npm install webhook-hmac-kit
```

## Quick Start

```ts
import { signWebhook, verifyWebhook } from 'webhook-hmac-kit';

// --- Sender ---
const payload = JSON.stringify({ event: 'payment.completed', amount: 4999 });
const timestamp = Math.floor(Date.now() / 1000);
const nonce = crypto.randomUUID();

const { signature } = await signWebhook({ secrets: 'whsec_your_secret_key', payload, timestamp, nonce });

// Send the payload with these three headers, built from the same values you just signed:
//   x-webhook-signature: signature
//   x-webhook-timestamp: String(timestamp)
//   x-webhook-nonce:     nonce

// --- Receiver ---
const result = await verifyWebhook({
  secrets: 'whsec_your_secret_key',
  payload: req.body,                         // the exact bytes you received, see below
  signature: req.headers['x-webhook-signature'],
  timestamp: Number(req.headers['x-webhook-timestamp']),
  nonce: req.headers['x-webhook-nonce'],
});
// result.valid === true (throws a typed error on failure)
```

`signWebhook` is not `async`: it validates its arguments synchronously, so a bad one
throws immediately, and returns a plain `Promise` for the HMAC step alone.
`verifyWebhook` is `async` throughout.

`payload` must be the exact bytes that went on the wire, not a re-serialised object.
Configure your framework to hand you the raw body (`express.raw()`, Fastify's
`rawBody`, NestJS's `rawBody: true`) and pass that straight through. Never
`JSON.parse` then `JSON.stringify` before verifying: that changes key order and
whitespace and breaks the signature. Verify first, parse second.

## Wire Format

The signed value is:

```
v2.{timestamp}.{nonce}.{payload}
```

built as bytes: the `v2.{timestamp}.{nonce}.` prefix is UTF-8 encoded, and the payload
follows unchanged, as the exact bytes it arrived in if you passed a `Uint8Array`, or
UTF-8 encoded if you passed a string. The signature header carries the version and a
lower-case hex digest, nothing else:

```
x-webhook-signature: v2=<64 lower-case hex characters>
```

Upper-case hex is rejected. A sender in another language must format the digest with
`%x`, not `%X`.

- **Nonce** must match `^[A-Za-z0-9_-]{1,64}$`, checked before any HMAC work runs. Dot-free
  by construction: the dot is the field delimiter, so a nonce that could contain one
  would make the encoding ambiguous.
- **Timestamp** is Unix seconds, a non-negative integer, matching `^(0|[1-9]\d*)$` on
  the wire: no leading zeros, no `+`, no exponent form, no whitespace. The value that
  gets checked is the value the sender actually signed, not whatever `Number()` coerces.
- **Tolerance** defaults to 300 seconds, checked as `|now - timestamp| <= tolerance`.
  Pass `tolerance` to `verifyWebhook` to change it.

## Rotation

```ts
await verifyWebhook({ secrets: [currentSecret, retiringSecret], ...rest });
```

Sign with one secret. Verify against a list: a signature made with any entry in it is
accepted. Keep the new secret first and the retiring one after it while both are live,
then drop the old one. A list may hold at most 16 distinct secrets; duplicates are
collapsed before that cap is applied.

## Replay Protection

```ts
await verifyWebhook({
  ...rest,
  nonceValidator: async (nonce) => {
    const key = `webhook:nonce:${nonce}`;
    if (await redis.exists(key)) return false;
    await redis.set(key, '1', 'EX', 300);
    return true;
  },
});
```

This library does not store anything. It makes the nonce a safe cache key, dot-free,
bounded length, and calls your `nonceValidator` after the signature has already
checked out, never before. Replay protection is exactly as strong as the store behind
that callback: its TTL needs to be at least your tolerance window, and it needs to be
shared across every receiving instance, or a nonce accepted on one instance replays
cleanly on another.

## Adapters

All three need the raw request body, same as the core functions.

### Express

```ts
import { webhookVerifier } from 'webhook-hmac-kit/express';

app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),  // req.body must stay bytes here
  webhookVerifier({
    secrets: [process.env.WEBHOOK_SECRET_CURRENT, process.env.WEBHOOK_SECRET_OLD],
    onError: (err) => logger.warn('webhook rejected', err),
  }),
  (req, res) => {
    // req.webhookVerified === true; req.body is still bytes, parse it yourself.
    res.sendStatus(200);
  },
);
```

### Fastify

```ts
import fastifyRawBody from 'fastify-raw-body';
import { webhookPlugin } from 'webhook-hmac-kit/fastify';

await app.register(fastifyRawBody);
await app.register(webhookPlugin, { secrets: process.env.WEBHOOK_SECRET });

app.post('/webhook', { preHandler: app.verifyWebhook }, async (request) => {
  return { ok: true };
});
```

### NestJS

```ts
// main.ts: request.rawBody needs this at bootstrap
const app = await NestFactory.create(AppModule, { rawBody: true });

// webhook.controller.ts
import { UseGuards, Post } from '@nestjs/common';
import { WebhookGuard } from 'webhook-hmac-kit/nest';

@UseGuards(WebhookGuard)
@Post('webhook')
handleWebhook() {
  return { ok: true };
}
```

`WebhookModule.forRoot({ secrets: ... })` registers `WEBHOOK_OPTIONS` and `WebhookGuard`
in one call, but `WebhookGuard` takes its options as a constructor argument, so it is not
injectable as a bare class provider: Nest has no way to resolve that argument on its own,
and construction fails. Provide it with a factory instead:

```ts
import { WebhookGuard, WEBHOOK_OPTIONS } from 'webhook-hmac-kit/nest';

providers: [
  { provide: WEBHOOK_OPTIONS, useValue: { secrets: process.env.WEBHOOK_SECRET } },
  { provide: WebhookGuard, useFactory: (options) => new WebhookGuard(options), inject: [WEBHOOK_OPTIONS] },
],
```

or skip Nest's container for the guard entirely and construct it yourself.

**Nest exception note.** `WebhookGuard` throws its own local exception class, because
this library has no dependency on `@nestjs/common` and so cannot throw *its*
`HttpException`. Nest's `BaseExceptionFilter` matches by `instanceof` against its own
class, so a global exception filter renders this as a 500, not the intended 401,
unless you catch and re-map it: the intended status is on `.getStatus()`, the real
reason is in `onError` either way.

## Error Handling

Every verification failure throws a typed error. Adapters answer every one of them
with the same status and body:

| Error class | Code |
|---|---|
| `WebhookSignatureError` | `WEBHOOK_SIGNATURE_INVALID` |
| `WebhookTimestampError` | `WEBHOOK_TIMESTAMP_EXPIRED` / `WEBHOOK_TIMESTAMP_INVALID` |
| `WebhookNonceError` | `WEBHOOK_NONCE_REPLAYED` / `WEBHOOK_NONCE_INVALID` |

All three extend `WebhookError`, so `catch (err) { if (err instanceof WebhookError) }`
is enough to tell a verification failure from anything else. `WebCryptoUnavailableError`,
thrown when the runtime has no Web Crypto, deliberately does not extend it: it means
the receiver is broken, not that the request failed to verify, so adapters answer it
with 500 instead of 401.

## Threat Model

- **The signature covers the exact bytes on the wire, end to end.** Pass the raw
  bytes you sent or received: a `Uint8Array`, or the exact string, never a re-parsed
  and re-serialised object, and never a body decoded to a string and then discarded
  for something else. Getting this wrong used to be able to make two different
  payloads verify against one signature (fixed in 2.0.0, see the CHANGELOG).
- **Replay protection is exactly as strong as the `nonceValidator` you supply.** This
  library never caches anything itself; it only makes the nonce a safe cache key.
  A store with a TTL shorter than your tolerance window, one that fails open, or one
  that isn't shared across instances gives you no replay protection at all.
- **This is integrity and authenticity only.** There is no confidentiality (HTTPS is
  required and is not checked here), no protection once the shared secret leaks, and
  no payload size limit: enforce that at your HTTP layer. Every verification failure
  answers the same 401 with the same body on purpose; the specific reason is only
  available through `onError`, never on the wire.

## Runtime Support

Node ≥22, Cloudflare Workers, Deno, Bun. Vercel Edge is not supported: its runtime is
being wound down (Next.js 16.3 removed `runtime: 'edge'`).

`globalThis.crypto.subtle` must exist. It does on all of the above by default. A Node
process started with `--no-experimental-global-webcrypto` does not have it: drop that
flag, or install the global yourself before importing this library:

```ts
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
```

(in CommonJS, the same fix is `globalThis.crypto ??= require('node:crypto').webcrypto`).

There is no fallback inside this library: a literal `node:crypto` import gets resolved
at bundle time by esbuild, wrangler and Metro whether or not the surrounding code can
run it, so a guarded import would cost every bundled build for nothing.

## Signature Comparison

Verification compares digests with a Double-HMAC blind rather than trusting the
runtime's own constant-time primitive: draw a random key, HMAC both the expected and
the presented digest under it, and compare those results instead. This exists because
constant-time HMAC verification is only required by the Web Crypto editor's draft
(w3c/webcrypto PR #553), not by any published Recommendation, and Node itself shipped
a plain `memcmp` in its own HMAC verify path until CVE-2026-21713 was patched (v20.20.2,
v22.22.2, v24.14.1, v25.8.2). Since this library does not control which patch level a
caller runs, it does not rely on the host's compare being constant-time in the first
place. Defence in depth: no exploit of the underlying Node bug is demonstrated in the
sources above. Cost: 3 `subtle.sign` and 2 `subtle.importKey` calls per configured
secret to verify, 1 `importKey` and 1 `sign` to sign, fine for a webhook receiver, so
don't put a 16-entry rotation list on a request path that isn't one.

## Test Vectors

All vectors below use secret `whsec_test_secret_key_1234567890`, `SIGNATURE_VERSION`
`v2` and timestamp `1700000000`. The full set, with the canonical string for each text
payload, is in `test/vectors.ts`.

| Name | Nonce | Payload | Signature |
|---|---|---|---|
| basic JSON | `nonce_abc123` | `{"event":"payment.completed","amount":4999}` | `v2=e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887` |
| empty payload | `nonce_empty001` | *(empty)* | `v2=048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa` |
| unicode payload | `nonce_unicode01` | `{"name":"Héllo Wörld","emoji":"🚀"}` | `v2=51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2` |
| byte payload, not valid UTF-8 | `nonce_bytes001` | `7b ff 7d` (hex) | `v2=6bcc8aabb3021f06f7cb713985154d03ca3916082148444bd0cc75e3837cd430` |

## License

MIT
