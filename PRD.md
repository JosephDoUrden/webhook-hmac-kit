# webhook-hmac-kit

Production-grade Webhook Signing & Verification Toolkit  
(HMAC-SHA256, replay protection, Stripe-style security)

---

## 1. Overview

`webhook-hmac-kit` is a lightweight, production-ready toolkit for signing and verifying webhook requests using HMAC-SHA256.

It provides a **generic, Stripe-style security model** that can be used across platforms such as Salesforce, Workato, Stripe-like APIs, or any custom webhook integration.

The library focuses on **correctness, security, and interoperability**, avoiding common pitfalls found in many webhook implementations.

---

## 2. Problem Statement

Webhook security is widely discussed but rarely implemented correctly.

Common issues:
- No replay attack protection
- Incorrect HMAC payload signing (JSON re-serialization issues)
- Missing timestamp validation
- Platform-specific implementations that are not reusable
- Poor documentation and lack of test vectors

This leads to:
- Vulnerable integrations
- Hard-to-debug signature mismatches
- Inconsistent security practices across teams

---

## 3. Goals

- Provide a **generic, reusable webhook security standard**
- Match **Stripe-level best practices**
- Be simple to adopt in existing Node.js backends
- Avoid opinionated frameworks
- Work with raw HTTP bodies (critical for correctness)

---

## 4. Non-Goals

- No framework-specific adapters (Express/Nest/Fastify wrappers can come later)
- No encryption (signing only, not payload confidentiality)
- No persistence layer (nonce storage handled by consumers)

---

## 5. Core Features

### 5.1 HMAC Signing
- Algorithm: `HMAC-SHA256`
- Supports configurable version prefix (e.g. `v1`)
- Deterministic canonical string generation

### 5.2 Canonical String Format

```

v1:{timestamp}:{nonce}:{raw_body}

````

Rules:
- `raw_body` must be the exact byte string received
- No JSON parsing or re-stringifying
- UTF-8 only

---

### 5.3 Timestamp Validation
- Configurable tolerance window (default: ±5 minutes)
- Rejects expired or future-dated requests

---

### 5.4 Replay Attack Protection
- Nonce-based replay prevention
- Consumer provides nonce store (Redis, DB, memory)
- Toolkit exposes validation hooks

---

### 5.5 Verification API
- Constant-time signature comparison
- Clear error states:
  - Invalid signature
  - Expired timestamp
  - Replayed nonce

---

### 5.6 Test Vectors
- Deterministic test cases
- Cross-language compatibility
- Enables platform verification (Salesforce, Workato, etc.)

---

## 6. API Design

### 6.1 Signing

```ts
signWebhook({
  secret,
  payload,      // raw string
  timestamp,
  nonce,
  version?: 'v1'
}) => {
  signature: string
}
````

---

### 6.2 Verification

```ts
verifyWebhook({
  secret,
  payload,      // raw string
  signature,
  timestamp,
  nonce,
  tolerance?: number,
  nonceValidator?: (nonce: string) => Promise<boolean>
}) => {
  valid: boolean
}
```

---

## 7. Security Considerations

* Uses `crypto.timingSafeEqual`
* Rejects parsed JSON inputs
* Explicitly documents raw body handling
* Avoids hidden magic or auto-parsing

---

## 8. Tech Stack

* Language: TypeScript
* Runtime: Node.js ≥ 18
* No external crypto dependencies
* Fully tree-shakeable
* ESM + CJS support

---

## 9. Documentation

* README with:

  * High-level explanation
  * Correct vs incorrect implementations
  * Platform examples (Salesforce, Workato)
* Inline TSDoc comments
* Security checklist

---

## 10. Success Metrics

* GitHub stars from backend & integration engineers
* Adoption in real-world webhook consumers
* Referenced in webhook security discussions

---

## 11. Future Enhancements

* Framework adapters (Express / Fastify / Nest)
* Language ports (Go, Python)
* OpenTelemetry hooks
* CLI for generating test vectors

---

## 12. License

MIT