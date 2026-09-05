# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No — different wire format, no fixes are backported |

## Reporting a Vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/JosephDoUrden/webhook-hmac-kit/security/advisories/new)
on this repository (Security tab → Report a vulnerability).

**Do not open a public issue for a security vulnerability.**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix, if you have one

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and release**: as soon as practical, typically within 14 days for a critical issue

## Signature Comparison

Verification compares signatures with a Double-HMAC blind: a random key is drawn per
comparison, both the expected and presented digest are HMAC'd under it, and the two
results are compared — instead of trusting the host runtime's own constant-time
primitive, or having one at all.

The reason: Web Crypto's HMAC verify has only been required to run in constant time
since the editor's draft added it (w3c/webcrypto PR #553, 26 Mar 2026) — neither the
2017 Recommendation nor the Level 2 First Public Working Draft says so, and there is
no web-platform-test for it. Node itself shipped a plain `memcmp` in its HMAC verify
path until CVE-2026-21713 was fixed in v20.20.2, v22.22.2, v24.14.1 and v25.8.2
(24 Mar 2026). This library does not know,
and cannot control, which patch level a consumer runs — so its own comparison does not
depend on the runtime's compare being constant-time in the first place, patched or not.

This is defence in depth, not a response to a demonstrated exploit: no remote exploit
of the underlying Node bug is known to us.

## Out of Scope

- **Transport security.** This library signs and verifies payloads; it assumes HTTPS
  is already in place and does not check the connection.
- **Secret leakage.** If a shared secret leaks, every signature made with it is
  meaningless. Rotate it via the `secrets` list.
- **Payload size limits.** Enforce these at your HTTP layer, before the body reaches
  this library.
