# webhook-hmac-kit

Lightweight, production-ready toolkit for signing and verifying webhook requests using HMAC-SHA256. Implements a Stripe-style security model with timestamp validation and replay protection.

- Zero runtime dependencies (uses Node.js built-in `crypto`)
- Dual format: ESM + CJS, fully tree-shakeable
- TypeScript-first with strict types
- Constant-time signature comparison

## Install

```bash
npm install webhook-hmac-kit
```

## Quick Start

```typescript
import { signWebhook, verifyWebhook } from 'webhook-hmac-kit';

// --- Sender side ---
const { signature } = signWebhook({
  secret: 'whsec_your_secret_key',
  payload: rawBody,           // the exact bytes you'll send
  timestamp: Math.floor(Date.now() / 1000),
  nonce: crypto.randomUUID(),
});
// Send signature, timestamp, and nonce as headers alongside the payload

// --- Receiver side ---
const result = await verifyWebhook({
  secret: 'whsec_your_secret_key',
  payload: rawBody,           // the exact bytes received over the wire
  signature: req.headers['x-webhook-signature'],
  timestamp: Number(req.headers['x-webhook-timestamp']),
  nonce: req.headers['x-webhook-nonce'],
});
// result.valid === true (throws on failure)
```

## API Reference

### `signWebhook(options): SignWebhookResult`

Synchronous. Computes an HMAC-SHA256 signature over a canonical string.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret` | `string` | Yes | Shared secret key |
| `payload` | `string` | Yes | Raw request body (exact bytes) |
| `timestamp` | `number` | Yes | Unix timestamp in seconds |
| `nonce` | `string` | Yes | Unique request identifier |
| `version` | `string` | No | Canonical string version prefix (default: `'v1'`) |

Returns `{ signature: string }` — hex-encoded HMAC-SHA256.

### `verifyWebhook(options): Promise<VerifyWebhookResult>`

Async. Verifies a webhook signature with timestamp and replay protection.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret` | `string` | Yes | Shared secret key |
| `payload` | `string` | Yes | Raw request body (exact bytes) |
| `signature` | `string` | Yes | Hex-encoded signature to verify |
| `timestamp` | `number` | Yes | Unix timestamp in seconds |
| `nonce` | `string` | Yes | Unique request identifier |
| `tolerance` | `number` | No | Max age in seconds (default: `300`) |
| `nonceValidator` | `(nonce: string) => Promise<boolean>` | No | Returns `false` if nonce was already seen |

Returns `{ valid: true }` on success. Throws a typed error on failure:

| Error Class | Code | Meaning |
|-------------|------|---------|
| `WebhookTimestampError` | `WEBHOOK_TIMESTAMP_EXPIRED` | Timestamp outside tolerance window |
| `WebhookSignatureError` | `WEBHOOK_SIGNATURE_INVALID` | HMAC does not match |
| `WebhookNonceError` | `WEBHOOK_NONCE_REPLAYED` | `nonceValidator` returned `false` |

All three extend `WebhookError`, which extends `Error`.

```typescript
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
    // Request too old or too far in the future
  } else if (err instanceof WebhookSignatureError) {
    // Payload was tampered with, or wrong secret
  } else if (err instanceof WebhookNonceError) {
    // Duplicate delivery / replay attack
  }
}
```

### `buildCanonicalString(version, timestamp, nonce, payload): string`

Builds the deterministic string that gets signed. Exported for debugging and cross-language verification.

## Why Raw Body Matters

HMAC signs exact bytes. If you parse the body as JSON and re-serialize it, you'll get a different string:

```typescript
const raw = '{"amount": 4999, "currency": "usd"}';

// After parse + stringify, key order and whitespace can change:
JSON.stringify(JSON.parse(raw));
// '{"amount":4999,"currency":"usd"}'  <-- different bytes!

// This breaks the signature:
signWebhook({ ..., payload: raw });                        // signs original
signWebhook({ ..., payload: JSON.stringify(JSON.parse(raw)) }); // different signature!
```

Always use the raw, unparsed request body for signing and verification.

## Common Webhook Security Mistakes

1. **Using `===` for signature comparison** — vulnerable to timing attacks. This library uses `crypto.timingSafeEqual`.

2. **No timestamp validation** — without timestamps, a captured request can be replayed indefinitely. This library rejects requests outside a configurable tolerance window (default: 5 minutes).

3. **No nonce checking** — even with timestamps, an attacker can replay a request within the tolerance window. Use the `nonceValidator` callback backed by Redis, a database, or an in-memory store.

4. **Parsing the body before verifying** — middleware that parses JSON before your webhook handler runs will re-serialize the body, breaking the signature. Verify first, parse second.

5. **Logging secrets** — never log your webhook secret. If you need to debug signatures, log the canonical string or the computed vs. received signature hashes.

## Platform Examples

### Express.js

```typescript
import express from 'express';
import { verifyWebhook, WebhookError } from 'webhook-hmac-kit';

const app = express();

// Use express.raw() to get the unparsed body as a Buffer
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    await verifyWebhook({
      secret: process.env.WEBHOOK_SECRET,
      payload: req.body.toString('utf-8'),
      signature: req.headers['x-webhook-signature'],
      timestamp: Number(req.headers['x-webhook-timestamp']),
      nonce: req.headers['x-webhook-nonce'],
    });

    const event = JSON.parse(req.body.toString('utf-8'));
    // Process the verified event...
    res.sendStatus(200);
  } catch (err) {
    if (err instanceof WebhookError) {
      res.status(401).json({ error: err.code });
    } else {
      res.sendStatus(500);
    }
  }
});
```

### Sending webhooks (Salesforce-style)

```typescript
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

await fetch('https://your-endpoint.com/webhook', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Webhook-Signature': signature,
    'X-Webhook-Timestamp': String(timestamp),
    'X-Webhook-Nonce': nonce,
  },
  body: payload,
});
```

### Receiving webhooks (Workato-style)

```typescript
import { verifyWebhook, WebhookTimestampError } from 'webhook-hmac-kit';

export async function handleWebhook(rawBody: string, headers: Record<string, string>) {
  const result = await verifyWebhook({
    secret: process.env.WEBHOOK_SECRET!,
    payload: rawBody,
    signature: headers['x-webhook-signature']!,
    timestamp: Number(headers['x-webhook-timestamp']),
    nonce: headers['x-webhook-nonce']!,
    nonceValidator: async (nonce) => {
      // Check against your store (Redis, DB, etc.)
      const seen = await redis.exists(`nonce:${nonce}`);
      if (seen) return false;
      await redis.set(`nonce:${nonce}`, '1', 'EX', 600); // expire after 10 min
      return true;
    },
  });

  return result; // { valid: true }
}
```

## Canonical String Format

All signatures are computed over a canonical string with the format:

```
{version}:{timestamp}:{nonce}:{payload}
```

For version `v1` (the default):

```
v1:1700000000:nonce_abc123:{"event":"payment.completed","amount":4999}
```

The payload is included verbatim — no encoding, no escaping. Colons in the payload are unambiguous because the version, timestamp, and nonce fields are parsed left-to-right with a known count of delimiters.

## Test Vectors

These vectors can be used for cross-language verification. All use the secret `whsec_test_secret_key_1234567890` and version `v1`.

| Payload | Timestamp | Nonce | Expected Signature |
|---------|-----------|-------|--------------------|
| `{"event":"payment.completed","amount":4999}` | `1700000000` | `nonce_abc123` | `dfa71af8832a81f0b996c3411de0b29f02a9292256a24ecf363465d3285bdc6b` |
| *(empty)* | `1700000000` | `nonce_empty001` | `96771f2cf8576c2154f7fbcdcea8840087539ca78ce3a5b91539cce7354b0d05` |
| `{"name":"Héllo Wörld","emoji":"🚀"}` | `1700000000` | `nonce_unicode01` | `0907a577eb997d1d8d355051bd50efcb73af1075d04353c437e931b3f92f4f95` |
| `{  "key"  :  "value"  }` | `1700000000` | `nonce_ws001` | `bb75675d65f0d591e92808b7aee2c90102ed4749933190b67e1cdbd3d04fbbef` |
| `{"time":"12:30:45","url":"https://example.com"}` | `1700000000` | `nonce_colon001` | `5270d1dd6e8807d6a92a933e6640505ff0226e4807c00d3dc70d9570fce1362e` |

## Security Considerations

- **Constant-time comparison**: Signatures are compared using `crypto.timingSafeEqual` to prevent timing attacks.
- **Replay protection**: Combine timestamp validation with nonce checking for full replay protection. The library provides the mechanism; you provide the nonce storage.
- **Secret rotation**: When rotating secrets, temporarily verify against both old and new secrets during the transition period. The library doesn't handle this — implement it in your verification layer.
- **Transport security**: HMAC signing protects integrity, not confidentiality. Always use HTTPS for webhook delivery.
- **Payload size**: The library does not enforce payload size limits. Apply limits at the HTTP layer to prevent abuse.

## License

MIT
