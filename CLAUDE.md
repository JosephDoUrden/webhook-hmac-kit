# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`webhook-hmac-kit` is a lightweight, production-ready toolkit for signing and verifying webhook requests using HMAC-SHA256. It implements a Stripe-style security model with replay protection. See `PRD.md` for the full product requirements.

## Tech Stack

- TypeScript on Node.js >= 18
- No external crypto dependencies (uses Node.js built-in `crypto` module)
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

### Canonical String Format

All signing/verification uses a deterministic canonical string:
```
v1:{timestamp}:{nonce}:{raw_body}
```

### Critical Security Rules

- **Raw body only**: The `payload` parameter must be the exact byte string received over the wire. Never JSON.parse then JSON.stringify — this changes key ordering and whitespace, breaking signatures.
- **Constant-time comparison**: All signature comparisons must use `crypto.timingSafeEqual`. Never use `===` for signature strings.
- **Timestamp validation**: Default tolerance is ±5 minutes. Reject expired and future-dated requests.
- **Nonce-based replay protection**: The library does not own nonce storage. Consumers provide a `nonceValidator` callback (can be backed by Redis, DB, or in-memory store).

### Core API Surface

Two primary functions:

- `signWebhook({ secret, payload, timestamp, nonce, version? })` → `{ signature }`
- `verifyWebhook({ secret, payload, signature, timestamp, nonce, tolerance?, nonceValidator? })` → `{ valid }`

### Error States

Verification must distinguish between:
- Invalid signature
- Expired timestamp
- Replayed nonce

### Scope Boundaries

- No framework-specific adapters (Express/Fastify/Nest are future work)
- No encryption — signing only
- No built-in persistence layer for nonces
