export type WebhookErrorCode =
  | 'WEBHOOK_SIGNATURE_INVALID'
  | 'WEBHOOK_TIMESTAMP_EXPIRED'
  | 'WEBHOOK_TIMESTAMP_INVALID'
  | 'WEBHOOK_NONCE_REPLAYED'
  | 'WEBHOOK_NONCE_INVALID';

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
