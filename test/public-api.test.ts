import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

describe('public surface', () => {
  it('exports the byte builder and not the string one', () => {
    // buildCanonicalString looks hashable and is not: it is the readable form, and handing it to
    // createHmac is exactly the mistake the v2 work was about. It stays internal, for the test
    // vectors and for anything that needs to show what was signed.
    expect(Object.keys(api)).toContain('buildCanonicalBytes');
    expect(Object.keys(api)).not.toContain('buildCanonicalString');
  });

  it('cannot be asked to format a scheme version it does not implement', () => {
    expect(api.formatSignature(new Uint8Array(32))).toBe(`v2=${'00'.repeat(32)}`);
    expect(api.formatSignature).toHaveLength(1);
  });

  // Every error a consumer can catch is reachable by name. Catching by message, or by reading
  // .name off an Error, is what people do when the class is not exported, and both break on the
  // next wording change.
  it('exports every error class it can throw', () => {
    for (const name of [
      'WebhookError',
      'WebhookSignatureError',
      'WebhookTimestampError',
      'WebhookNonceError',
      'WebCryptoUnavailableError',
    ]) {
      expect(Object.keys(api)).toContain(name);
    }
  });

  // Load-bearing, not pedantry: the adapters answer 401 for a WebhookError and 500 for anything
  // else. A runtime with no Web Crypto is the receiver being broken, not the caller's signature
  // being wrong, so it must never become a WebhookError and start reporting itself as a rejected
  // webhook.
  it('keeps the Web Crypto failure outside the WebhookError hierarchy', () => {
    const error = new api.WebCryptoUnavailableError();

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(api.WebCryptoUnavailableError);
    expect(error).not.toBeInstanceOf(api.WebhookError);
    expect(error.name).toBe('WebCryptoUnavailableError');
    expect(error.message).toMatch(/--no-experimental-global-webcrypto/);
  });

  // The Standard Webhooks module ships as three functions and its types, and nothing else. There is
  // no adapter flag: one endpoint speaks one scheme, and a boolean that swapped which headers an
  // adapter reads would have given `secrets` two meanings and quietly dropped replay protection.
  it('exports the Standard Webhooks functions and no adapter switch', () => {
    for (const name of [
      'parseStandardWebhooksSecret',
      'signStandardWebhooks',
      'verifyStandardWebhooks',
    ]) {
      expect(Object.keys(api)).toContain(name);
    }
    expect(Object.keys(api)).not.toContain('buildStandardWebhooksBytes');
  });

  // StandardWebhooksSecret and WebhookSecret are both `string | Uint8Array`, so they are the same
  // type and the compiler will not stop anyone swapping one for the other. The separation is
  // documentary: two names, each with the encoding written on it, so the reader of a call site can
  // see which meaning is in play. That matters because passing a whsec_ string where a raw secret
  // belongs is not an error at all - it is a different key, silently. Nothing here can enforce it,
  // and pretending otherwise would be worse than saying so.
  it('names the two secret types separately, without being able to enforce the distinction', () => {
    const swSecret: api.StandardWebhooksSecret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
    const headers: api.StandardWebhooksHeaders = {
      'webhook-id': 'msg_1',
      'webhook-timestamp': '1614265330',
      'webhook-signature': 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
    };

    expect(api.parseStandardWebhooksSecret(swSecret)).toHaveLength(24);
    expect(headers['webhook-id']).toBe('msg_1');

    // The same string through the two APIs, to show what the naming is up against: 24 base64-
    // decoded bytes on one side, 38 UTF-8 bytes on the other, no error either way.
    expect(api.normalizeSecrets(swSecret)[0]).toHaveLength(swSecret.length);
  });

  // Nothing on the public surface asks for or hands back a Buffer. The digest a caller parses out
  // of a header has to be usable on a runtime that has never heard of Node.
  it('speaks Uint8Array, not Buffer', () => {
    const parsed = api.parseSignature(`v2=${'ab'.repeat(32)}`);
    expect(parsed?.digest.constructor).toBe(Uint8Array);
    expect(api.normalizeSecrets('whsec_x')[0].constructor).toBe(Uint8Array);
    expect(api.buildCanonicalBytes(1000, 'n', 'x').constructor).toBe(Uint8Array);
  });
});
