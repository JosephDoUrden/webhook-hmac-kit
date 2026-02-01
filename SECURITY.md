# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in webhook-hmac-kit, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to the maintainers or use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and release**: as soon as practical, typically within 14 days for critical issues

## Security Design

This library follows these security principles:

- **Constant-time comparison** using `crypto.timingSafeEqual` to prevent timing attacks
- **Timestamp validation** to limit the replay window
- **Nonce support** for full replay protection (storage is consumer-provided)
- **Zero runtime dependencies** to minimize supply chain risk
- **Input validation** on security-critical parameters (secret, timestamp, tolerance)
