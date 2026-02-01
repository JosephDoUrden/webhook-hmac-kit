import { describe, expect, it } from 'vitest';
import {
  WebhookError,
  WebhookNonceError,
  WebhookSignatureError,
  WebhookTimestampError,
} from '../src/errors.js';

describe('WebhookError', () => {
  it('has correct name and code', () => {
    const err = new WebhookError('test', 'WEBHOOK_SIGNATURE_INVALID');
    expect(err.name).toBe('WebhookError');
    expect(err.code).toBe('WEBHOOK_SIGNATURE_INVALID');
    expect(err.message).toBe('test');
  });

  it('is an instance of Error', () => {
    const err = new WebhookError('test', 'WEBHOOK_SIGNATURE_INVALID');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(WebhookError);
  });
});

describe('WebhookSignatureError', () => {
  it('has correct name and code', () => {
    const err = new WebhookSignatureError();
    expect(err.name).toBe('WebhookSignatureError');
    expect(err.code).toBe('WEBHOOK_SIGNATURE_INVALID');
  });

  it('has default message', () => {
    const err = new WebhookSignatureError();
    expect(err.message).toBe('Webhook signature is invalid');
  });

  it('accepts custom message', () => {
    const err = new WebhookSignatureError('custom message');
    expect(err.message).toBe('custom message');
  });

  it('is instance of WebhookError and Error', () => {
    const err = new WebhookSignatureError();
    expect(err).toBeInstanceOf(WebhookSignatureError);
    expect(err).toBeInstanceOf(WebhookError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe('WebhookTimestampError', () => {
  it('has correct name and code', () => {
    const err = new WebhookTimestampError();
    expect(err.name).toBe('WebhookTimestampError');
    expect(err.code).toBe('WEBHOOK_TIMESTAMP_EXPIRED');
  });

  it('has default message', () => {
    const err = new WebhookTimestampError();
    expect(err.message).toBe('Webhook timestamp has expired');
  });

  it('accepts custom message', () => {
    const err = new WebhookTimestampError('too old');
    expect(err.message).toBe('too old');
  });

  it('is instance of WebhookError and Error', () => {
    const err = new WebhookTimestampError();
    expect(err).toBeInstanceOf(WebhookTimestampError);
    expect(err).toBeInstanceOf(WebhookError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe('WebhookNonceError', () => {
  it('has correct name and code', () => {
    const err = new WebhookNonceError();
    expect(err.name).toBe('WebhookNonceError');
    expect(err.code).toBe('WEBHOOK_NONCE_REPLAYED');
  });

  it('has default message', () => {
    const err = new WebhookNonceError();
    expect(err.message).toBe('Webhook nonce has been replayed');
  });

  it('accepts custom message', () => {
    const err = new WebhookNonceError('seen before');
    expect(err.message).toBe('seen before');
  });

  it('is instance of WebhookError and Error', () => {
    const err = new WebhookNonceError();
    expect(err).toBeInstanceOf(WebhookNonceError);
    expect(err).toBeInstanceOf(WebhookError);
    expect(err).toBeInstanceOf(Error);
  });
});
