# webhook-hmac-kit

[![npm version](https://img.shields.io/npm/v/webhook-hmac-kit)](https://www.npmjs.com/package/webhook-hmac-kit)
[![license](https://img.shields.io/npm/l/webhook-hmac-kit)](https://github.com/JosephDoUrden/webhook-hmac-kit/blob/main/LICENSE)

Verify [Standard Webhooks](https://www.standardwebhooks.com) requests (`webhook-id`,
`webhook-timestamp`, `webhook-signature`, `whsec_` secrets) over the raw bytes, with a
timestamp tolerance window and key rotation, and no runtime dependencies. A Web `Request`
adapter and Hono middleware cover Next.js route handlers, Workers, Deno and Bun. When you
control both ends, it also signs and verifies in its own format, with nonce-based replay
protection and adapters for Express, Fastify and NestJS as well.

Runs on Web Crypto only, so it works the same way on Node, Cloudflare Workers, Deno and
Bun with no bundler configuration and no runtime branch.

**2.0.0 is a breaking release.** The library's [own wire format](#own-format-v2) changed. See
[CHANGELOG.md](CHANGELOG.md) before upgrading in place: a v1 signature is refused outright,
with no dual-accept window.

## Install

```bash
npm install webhook-hmac-kit
```

## Quick Start

### Receiving

```ts
import { verifyStandardWebhooks, WebhookError } from 'webhook-hmac-kit';

// rawBody: the body exactly as received, as a Uint8Array.
// headers: the request headers as an object, e.g. Node's req.headers.
try {
  await verifyStandardWebhooks({
    secrets: 'whsec_PLACEHOLDERxREPLACExWITHxYOURxOWNxSECRET',
    headers,
    payload: rawBody,
  });
} catch (err) {
  if (err instanceof WebhookError) return reject(401); // bad signature, stale timestamp
  throw err;                                           // your configuration, not the caller's
}

const event = JSON.parse(new TextDecoder().decode(rawBody)); // verify first, parse second
```

The examples use a placeholder; use the secret your sender gave you. Pass every live
secret as an array to rotate keys. `tolerance` changes the 300-second window. `now` (Unix
seconds) verifies a recorded request or a test vector against the time it was sent; it is
a testing aid, never something to set in production.

If your handler receives a Web `Request` (Next.js App Router, Hono, Workers, Deno, Bun),
`verifyStandardWebhooksRequest` from `webhook-hmac-kit/web` reads the body and does all of
this for you; see [Adapters](#adapters). The Express, Fastify and NestJS adapters verify
this library's own format only: there, get the raw body from your framework
(`express.raw()`, Fastify's `rawBody`, NestJS's `rawBody: true`) and call
`verifyStandardWebhooks` from your handler as above.

### Sending

```ts
import { signStandardWebhooks } from 'webhook-hmac-kit';

const body = JSON.stringify({ type: 'invoice.paid', data: { id: 'inv_123' } });

const headers = await signStandardWebhooks({
  secrets: 'whsec_PLACEHOLDERxREPLACExWITHxYOURxOWNxSECRET',
  messageId: 'msg_p5jXN8AQM9LWM0D4loKWxJek', // per event, the same on every retry
  timestamp: Math.floor(Date.now() / 1000),
  payload: body,
});

await fetch('https://example.com/webhook', {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body,
});
```

## Standard Webhooks

`verifyStandardWebhooks` resolves to `{ valid: true }` or throws the same `WebhookError`
subclasses as `verifyWebhook`, so the error handling below applies unchanged, for anything
that is a failed verification. Two kinds of failure are
not: a mistake in your own arguments (a `tolerance` that is not a non-negative finite
number, a secret outside the base64 grammar) throws a plain `Error` or `TypeError`, and
a runtime whose Web Crypto misbehaves throws a plain `Error` too, the same way
`WebCryptoUnavailableError` does. Neither is a `WebhookError`, so the adapters answer
them with 500 rather than 401: your configuration or your machine is wrong, not the
caller's signature.

Header names are matched case-insensitively, a single-entry array is unwrapped, an empty
string counts as missing, and two values for one header are refused rather than resolved.
Secrets are `whsec_`-prefixed base64, or a `Uint8Array` of raw key bytes;
`parseStandardWebhooksSecret` is exported if you want the bytes. A secret whose base64
length leaves a remainder of 1 is rejected here, where the upstream JavaScript library
decodes it anyway and silently gives you a key one character shorter than the one you
configured.

**Never use one secret for both schemes.** `v2.{ts}.{nonce}.{payload}` and a Standard
Webhooks message whose id is the literal `v2` and whose payload is `{nonce}.{payload}`
are byte-identical, so a signature minted under one scheme is a valid signature under
the other. Domain separation would close it and conformance forbids domain separation,
so the rule is operational: generate a separate secret. A test pins the collision.

**`webhook-id` is not a trust boundary.** Their signed value is
`{id}.{timestamp}.{payload}` with nothing constraining the id, so an id holding a dot
and a run of digits re-splits into a different, equally valid message carrying the same
signature. It cannot be fixed without emitting signatures no conforming receiver would
accept, so this module does not try, and gives you no replay hook keyed on it. If you
need replay protection with a key you can actually trust, use this package's
[own scheme](#own-format-v2), where the nonce is dot-free by construction.

### What differs on the way out and on the way in

|  | Signing | Verifying |
|---|---|---|
| Key length | 24–64 bytes, the spec's stated range | any non-empty key |
| Payload | must be well-formed UTF-8 | hashed as bytes; a string payload is UTF-8 encoded first |
| Message id | no `.`, no whitespace | anything non-empty |
| Signature entries | one `v1,<base64>` per secret, space-joined | unknown tags and malformed entries skipped |

A verifier weighs at most 16 signature entries, the same cap that bounds the secret list, because
the entry count arrives from the network and every entry is weighed against every configured
secret. A conforming sender emits one entry per live key, so nothing legitimate reaches it.

Each asymmetry is the lenient side facing the network. No reference library enforces
the key range, and upstream's own Python suite signs with a 23-byte key, so refusing a
short key on receive would break a live integration to make a point. Four reference
libraries disagree about a body that is not well-formed UTF-8 — Go signs the bytes,
Rust refuses the message, JavaScript and Python sign a mangled copy — so there is no
digest that satisfies all of them and the emitter refuses rather than producing one
some receivers compute differently; the verifier has no such problem and takes the
bytes as they arrive, which is Go's behaviour. Skipping unreadable signature entries is
what their rotation model needs and what their own tests require: they put a `v2,`
entry beside a valid one and expect the request to succeed.

### What the interop claim covers

This implementation reproduces the de-facto vector shared by six reference
implementations — the JavaScript, Go, Python, Ruby, PHP and C# test suites all pin the
same one — plus the Rust crate's own vector, both signing and verifying, byte for byte.
The two counts above describe different sets: six suites pin that vector, and the four
libraries whose payload handling was read at source (Go, Rust, JavaScript, Python) are
the ones that disagree about non-UTF-8 bodies.
Both are committed in `test/standard-webhooks-vectors.ts` with the upstream commit and
path they came from.

It does not cover: `svix-*` alias headers, the asymmetric `v1a` ed25519 tag, parsing
the payload as JSON (this library never parses a payload), or a body that is not
well-formed UTF-8, where the reference implementations do not agree with each other and
so no single behaviour can be conformant. There is no official conformance suite to
point at; those two vectors are what exists.

If your provider still sends the older `svix-id`, `svix-timestamp` and `svix-signature`
names, map them onto the `webhook-*` names before calling: the values are identical, and
`verifyStandardWebhooks` looks only for the specified names.

## Own format (v2)

When you control both the sender and the receiver, the library has a scheme of its own: a
dot-free nonce in the signed value, so replay protection can key on something
authenticated, plus framework adapters. Nobody else sends this format, so do not reach for
it to receive from a third party.

![demo](docs/demo.gif)

### Quick Start (v2)

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

### Wire Format

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
  Pass `tolerance` to `verifyWebhook` to change it. `now` is the system clock unless you
  pass `now` (Unix seconds), which both verifiers take. It is there for replaying a
  recorded request or a test vector, not for production traffic.

### Rotation

```ts
await verifyWebhook({ secrets: [currentSecret, retiringSecret], ...rest });
```

Sign with one secret. Verify against a list: a signature made with any entry in it is
accepted. Keep the new secret first and the retiring one after it while both are live,
then drop the old one. A list may hold at most 16 distinct secrets; duplicates are
collapsed before that cap is applied.

### Replay Protection

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

### Adapters

Every adapter needs the raw request body, same as the core functions. The Web and Hono
adapters read it themselves and verify either scheme, with one function per scheme rather
than a flag. Express, Fastify and NestJS verify the v2 format only; for Standard Webhooks
there, call `verifyStandardWebhooks` from your handler as in the
[Quick Start](#quick-start).

#### Web `Request`: Next.js, Workers, Deno, Bun

```ts
// app/api/webhook/route.ts (Next.js App Router)
import { verifyStandardWebhooksRequest } from 'webhook-hmac-kit/web';

export async function POST(request: Request) {
  const result = await verifyStandardWebhooksRequest(request, {
    secrets: process.env.WEBHOOK_SECRET!, // `!`: env values are string | undefined
    onError: (err) => console.warn('webhook rejected', err),
  });
  if (!result.ok) return result.response;

  const event = JSON.parse(new TextDecoder().decode(result.payload));
  // ...
  return new Response(null, { status: 204 });
}
```

The body is read once, as bytes, and handed back as `result.payload`: parse that, not the
request. If something has already read the body, the signed bytes are gone, and the result
is a 500 whose `error` says to verify first or pass a `request.clone()` taken earlier.
`result.response` is a ready JSON `Response`; `result.status` and `result.error` are there
if you would rather build your own. Never put `result.error` in a response: serialised, it
exposes its `code` and `name` and brings back the distinction the uniform 401 hides, so
answer with `result.response` or a fixed body of your own (`error` is non-enumerable, so
serialising the whole result leaves it out). `verifyWebhookRequest` does the same for the v2 format
and takes the v2 options (`nonceValidator`, header names). Both take `now`, the testing aid
from the [Quick Start](#receiving), and so do both Hono middlewares. Anything else that hands you a
Web `Request` works the same way: a Workers `fetch` handler, `Deno.serve`, `Bun.serve`,
SvelteKit, Remix.

Statuses: 401 for every failed verification, including a missing Standard Webhooks header
(as in the Quick Start); 400 for a missing v2 header, as in the other adapters; 500 for a
configuration error. Fetch `Headers` fold a repeated header into one comma-joined value.
For v2 that value fails closed as a 401. In a Standard Webhooks signature list, the last
entry of every header value except the final one keeps the comma and is unreadable; the
rest still parse.

#### Hono

```ts
import { Hono } from 'hono';
import { standardWebhooksVerifier, type WebhookVariables } from 'webhook-hmac-kit/hono';

const app = new Hono<{ Variables: WebhookVariables }>();

app.post(
  '/webhook',
  standardWebhooksVerifier({ secrets: process.env.WEBHOOK_SECRET! }),
  (c) => {
    const event = JSON.parse(new TextDecoder().decode(c.get('webhookPayload')));
    // ...
    return c.body(null, 204);
  },
);
```

`webhookVerifier` is the v2 equivalent. On failure the middleware answers with `c.json`
and the route never runs; the statuses are the ones above. `hono` is not a dependency: the
middleware is typed against the parts of the context it uses.

#### Express

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

#### Fastify

```ts
import fastifyRawBody from 'fastify-raw-body';
import { webhookPlugin } from 'webhook-hmac-kit/fastify';

await app.register(fastifyRawBody);
await app.register(webhookPlugin, { secrets: process.env.WEBHOOK_SECRET });

app.post('/webhook', { preHandler: app.verifyWebhook }, async (request) => {
  return { ok: true };
});
```

#### NestJS

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

The vectors ship with the package, as JSON, in `vectors/`:

- `vectors/standard-webhooks.json`: Standard Webhooks. The two upstream reference
  vectors, a body of every byte from 0 to 255 (the known answer from
  standard-webhooks/standard-webhooks#348), a lone `0xff` byte and the U+FFFD it
  decodes to (two different signatures, which is the point), rotation, skipped `v2,`
  and malformed entries, the 16-entry cap, both sides of the tolerance window, a wrong
  key, a dotted message id, and a 23-byte key that verifies but will not sign.
- `vectors/v2.json`: this package's own scheme. The vectors in the table below plus an
  all-bytes body, rotation, upper-case and non-hex digests, an unsupported version, a
  wrong key, both sides of the window and a nonce with a dot in it.

Public test keys. Never use outside tests. Each file says so in its `note` field.

Each case has the secret, the message id or nonce, the timestamp, the payload as base64
(and as text where it is UTF-8), the signature or headers, and the outcome: `"valid"`,
`{ "error": "<code>" }` (verify must refuse), or `{ "reject": "sign" }` (the signer must
refuse). Every case also carries `now`, the Unix time the verifier should assume, so a
run gives the same answer whenever it happens. `direction` is `sign+verify` when a
signer must reproduce the signature, `verify-only` when the case is for receivers, and
`sign-only` for a case the signer must refuse; an `error` case is always `verify-only`.
This library refuses to sign a body that is not well-formed UTF-8, so every such case
is `verify-only`. `source` says where the value came from.

`conformance` is `spec` when any conforming implementation should agree with the case,
and `webhook-hmac-kit` when the case pins this library's own policy: the 16-entry cap,
refusing a key under 24 bytes at sign time, and the whole `v2` scheme. If you are
testing another implementation, treat every `error` case as "must reject" whatever
your error is called (the codes are this library's names), and skip the
`webhook-hmac-kit` cases if you like.

`scripts/gen-vectors.mjs` writes both files with `node:crypto` and never imports this
package, so no value in them is the library vouching for itself. Running it again gives
the same bytes, and CI checks that it does. The files are also importable, as
`webhook-hmac-kit/vectors/standard-webhooks.json` and `webhook-hmac-kit/vectors/v2.json`.

The package also installs a CLI:

```sh
npx webhook-hmac-kit vectors                   # print both corpora
npx webhook-hmac-kit vectors --scheme sw       # or one of them: sw, v2
npx webhook-hmac-kit vectors --verify my.json  # run a corpus file through this library
```

`--verify` prints one line per case and exits 1 if any case fails. To check another
implementation, load the JSON from that implementation's own tests.

The `v2` vectors below use secret `whsec_test_secret_key_1234567890` and timestamp
`1700000000`. The canonical string for each text payload is in `test/vectors.ts`.

| Name | Nonce | Payload | Signature |
|---|---|---|---|
| basic JSON | `nonce_abc123` | `{"event":"payment.completed","amount":4999}` | `v2=e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887` |
| empty payload | `nonce_empty001` | *(empty)* | `v2=048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa` |
| unicode payload | `nonce_unicode01` | `{"name":"Héllo Wörld","emoji":"🚀"}` | `v2=51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2` |
| byte payload, not valid UTF-8 | `nonce_bytes001` | `7b ff 7d` (hex) | `v2=6bcc8aabb3021f06f7cb713985154d03ca3916082148444bd0cc75e3837cd430` |

## License

MIT
