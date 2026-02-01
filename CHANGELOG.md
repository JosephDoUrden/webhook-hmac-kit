# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
