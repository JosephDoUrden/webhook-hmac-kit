export type WebhookErrorCode =
  | 'WEBHOOK_SIGNATURE_INVALID'
  | 'WEBHOOK_TIMESTAMP_EXPIRED'
  | 'WEBHOOK_TIMESTAMP_INVALID'
  | 'WEBHOOK_NONCE_REPLAYED'
  | 'WEBHOOK_NONCE_INVALID';

/**
 * Base class for every verification failure. The subclasses say which check failed, and that
 * detail is for logs and metrics on the receiving side.
 *
 * Do not let the distinction reach the wire. If an HTTP handler answers 400 for an expired
 * timestamp or 409 for a replayed nonce, an unauthenticated caller learns that its signature was
 * accepted and only a later check failed, which confirms the shared secret is still live. Map every
 * WebhookError to the same status (401) and the same body; the shipped adapters do this and expose
 * the specific error through their `onError` option instead.
 */
export class WebhookError extends Error {
  readonly code: WebhookErrorCode;

  constructor(message: string, code: WebhookErrorCode) {
    super(message);
    this.name = 'WebhookError';
    this.code = code;
  }
}

export class WebhookSignatureError extends WebhookError {
  constructor(message = 'Webhook signature is invalid') {
    super(message, 'WEBHOOK_SIGNATURE_INVALID');
    this.name = 'WebhookSignatureError';
  }
}

export class WebhookTimestampError extends WebhookError {
  constructor(
    message = 'Webhook timestamp has expired',
    code: Extract<
      WebhookErrorCode,
      'WEBHOOK_TIMESTAMP_EXPIRED' | 'WEBHOOK_TIMESTAMP_INVALID'
    > = 'WEBHOOK_TIMESTAMP_EXPIRED',
  ) {
    super(message, code);
    this.name = 'WebhookTimestampError';
  }
}

export class WebhookNonceError extends WebhookError {
  constructor(
    message = 'Webhook nonce has been replayed',
    code: Extract<
      WebhookErrorCode,
      'WEBHOOK_NONCE_REPLAYED' | 'WEBHOOK_NONCE_INVALID'
    > = 'WEBHOOK_NONCE_REPLAYED',
  ) {
    super(message, code);
    this.name = 'WebhookNonceError';
  }
}
