# webhook-hmac-kit

[![npm version](https://img.shields.io/npm/v/webhook-hmac-kit)](https://www.npmjs.com/package/webhook-hmac-kit)
[![npm downloads](https://img.shields.io/npm/dw/webhook-hmac-kit)](https://www.npmjs.com/package/webhook-hmac-kit)
[![license](https://img.shields.io/npm/l/webhook-hmac-kit)](https://github.com/JosephDoUrden/webhook-hmac-kit/blob/main/LICENSE)

Lightweight, production-ready toolkit for signing and verifying webhook requests using HMAC-SHA256.  
Implements a Stripe-style security model with timestamp validation and replay protection.

> Correct webhook security. No magic. No footguns.  
> Used in production systems handling financial & operational webhooks  
> (Salesforce, Workato-style integrations)

- Zero runtime dependencies (Node.js built-in `crypto`)
- Dual format: ESM + CJS, fully tree-shakeable
- TypeScript-first with strict types
- Constant-time signature comparison

---

## Install

```bash
npm install webhook-hmac-kit
```

---

## Quick Start

```ts
import { signWebhook, verifyWebhook } from 'webhook-hmac-kit';
import crypto from 'node:crypto';

// --- Sender side ---
const rawBody = JSON.stringify({ event: 'payment.completed', amount: 4999 });

const { signature } = signWebhook({
  secret: 'whsec_your_secret_key',
  payload: rawBody,                  // exact bytes you send
  timestamp: Math.floor(Date.now() / 1000),
  nonce: crypto.randomUUID(),
});

// Send signature, timestamp, and nonce as headers

// --- Receiver side ---
const result = await verifyWebhook({
  secret: 'whsec_your_secret_key',
  payload: rawBody,                  // exact bytes received
  signature: req.headers['x-webhook-signature'],
  timestamp: Number(req.headers['x-webhook-timestamp']),
  nonce: req.headers['x-webhook-nonce'],
});

// result.valid === true (throws on failure)
```

---

## API Reference

### `signWebhook(options): SignWebhookResult`

Synchronous. Computes an HMAC-SHA256 signature over a canonical string.

| Parameter   | Type     | Required | Description                              |
| ----------- | -------- | -------- | ---------------------------------------- |
| `secret`    | `string` | Yes      | Shared secret key                        |
| `payload`   | `string` | Yes      | Raw request body (exact bytes)           |
| `timestamp` | `number` | Yes      | Unix timestamp (seconds)                 |
| `nonce`     | `string` | Yes      | Unique request identifier                |
| `version`   | `string` | No       | Canonical version prefix (default: `v1`) |

Returns:

```ts
{ signature: string } // hex-encoded
```

---

### `verifyWebhook(options): Promise<VerifyWebhookResult>`

Async. Verifies signature, timestamp, and optional replay protection.

| Parameter        | Type                                  | Required | Description                              |
| ---------------- | ------------------------------------- | -------- | ---------------------------------------- |
| `secret`         | `string`                              | Yes      | Shared secret key                        |
| `payload`        | `string`                              | Yes      | Raw request body                         |
| `signature`      | `string`                              | Yes      | Hex-encoded signature                    |
| `timestamp`      | `number`                              | Yes      | Unix timestamp (seconds)                 |
| `nonce`          | `string`                              | Yes      | Unique request identifier                |
| `tolerance`      | `number`                              | No       | Max age in seconds (default: `300`)      |
| `nonceValidator` | `(nonce: string) => Promise<boolean>` | No       | Return `false` if nonce was already seen |

Returns `{ valid: true }` on success.
Throws a typed error on failure.

---

## Error Handling

All verification failures throw **typed errors** for precise handling.

| Error Class             | Code                        | Recommended HTTP Status |
| ----------------------- | --------------------------- | ----------------------- |
| `WebhookSignatureError` | `WEBHOOK_SIGNATURE_INVALID` | `401 Unauthorized`      |
| `WebhookTimestampError` | `WEBHOOK_TIMESTAMP_EXPIRED` | `400 Bad Request`       |
| `WebhookNonceError`     | `WEBHOOK_NONCE_REPLAYED`    | `409 Conflict`          |

```ts
import {
  verifyWebhook,
  WebhookTimestampError,
  WebhookSignatureError,
  WebhookNonceError,
} from 'webhook-hmac-kit';

try {
  await verifyWebhook({ ... });
} catch (err) {
  if (err instanceof WebhookTimestampError) {
    // Too old or too far in the future
  } else if (err instanceof WebhookSignatureError) {
    // Tampered payload or wrong secret
  } else if (err instanceof WebhookNonceError) {
    // Replay attack / duplicate delivery
  }
}
```

---

## Canonical String

All signatures are computed over:

```
{version}:{timestamp}:{nonce}:{payload}
```

Example (`v1`):

```
v1:1700000000:nonce_abc123:{"event":"payment.completed","amount":4999}
```

The payload is included **verbatim** — no encoding, escaping, or normalization.

---

## Why Raw Body Matters

HMAC signs **exact bytes**. Parsing JSON breaks signatures.

```ts
const raw = '{ "amount": 4999, "currency": "usd" }';

JSON.stringify(JSON.parse(raw));
// {"amount":4999,"currency":"usd"} ← different bytes

signWebhook({ payload: raw });                        // correct
signWebhook({ payload: JSON.stringify(JSON.parse(raw)) }); // ❌ mismatch
```

**Always verify first, parse second.**

---

## Common Webhook Security Mistakes

1. **Using `===` for signature comparison**
   → Vulnerable to timing attacks.
   This library uses `crypto.timingSafeEqual`.

2. **No timestamp validation**
   → Captured requests can be replayed forever.

3. **No nonce checking**
   → Requests can be replayed within the tolerance window.

4. **Parsing body before verification**
   → Breaks signatures due to re-serialization.

5. **Logging secrets**
   → Log canonical strings or hashes, never secrets.

---

## Platform Examples

### Express.js (Receiver)

```ts
import express from 'express';
import { verifyWebhook, WebhookError } from 'webhook-hmac-kit';

const app = express();

app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      await verifyWebhook({
        secret: process.env.WEBHOOK_SECRET!,
        payload: req.body.toString('utf-8'),
        signature: req.headers['x-webhook-signature'],
        timestamp: Number(req.headers['x-webhook-timestamp']),
        nonce: req.headers['x-webhook-nonce'],
      });

      const event = JSON.parse(req.body.toString('utf-8'));
      res.sendStatus(200);
    } catch (err) {
      if (err instanceof WebhookError) {
        res.status(401).json({ error: err.code });
      } else {
        res.sendStatus(500);
      }
    }
  }
);
```

---

### Redis Nonce Validator (Replay Protection)

```ts
nonceValidator: async (nonce) => {
  const key = `webhook:nonce:${nonce}`;
  const exists = await redis.exists(key);
  if (exists) return false;
  await redis.set(key, '1', 'EX', 300);
  return true;
};
```

---

### Sending Webhooks (Salesforce-style)

```ts
import { signWebhook } from 'webhook-hmac-kit';
import crypto from 'node:crypto';

const payload = JSON.stringify({ event: 'record.updated', id: '001xx000003DGbX' });
const timestamp = Math.floor(Date.now() / 1000);
const nonce = crypto.randomUUID();

const { signature } = signWebhook({
  secret: 'whsec_your_secret',
  payload,
  timestamp,
  nonce,
});
```

---

## Why not JWT?

JWTs are designed for **authentication**, not signing arbitrary HTTP payloads.

Webhook signatures must:

* Sign exact raw bytes
* Avoid JSON canonicalization issues
* Be cheap to verify

HMAC is simpler, safer, and battle-tested for webhook integrity.

---

## Test Vectors

All vectors use secret `whsec_test_secret_key_1234567890` and version `v1`.

| Payload                                       | Timestamp    | Nonce             | Expected Signature                                                 |
| --------------------------------------------- | ------------ | ----------------- | ------------------------------------------------------------------ |
| `{"event":"payment.completed","amount":4999}` | `1700000000` | `nonce_abc123`    | `dfa71af8832a81f0b996c3411de0b29f02a9292256a24ecf363465d3285bdc6b` |
| *(empty)*                                     | `1700000000` | `nonce_empty001`  | `96771f2cf8576c2154f7fbcdcea8840087539ca78ce3a5b91539cce7354b0d05` |
| `{"name":"Héllo Wörld","emoji":"🚀"}`         | `1700000000` | `nonce_unicode01` | `0907a577eb997d1d8d355051bd50efcb73af1075d04353c437e931b3f92f4f95` |

---

## Security Considerations

* Constant-time comparison
* Replay protection via timestamp + nonce
* Secret rotation supported at integration layer
* HTTPS required (integrity ≠ confidentiality)
* Apply payload size limits at HTTP layer

---

## License

MIT