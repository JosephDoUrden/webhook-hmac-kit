export type WebhookErrorCode =
  | 'WEBHOOK_SIGNATURE_INVALID'
  | 'WEBHOOK_TIMESTAMP_EXPIRED'
  | 'WEBHOOK_NONCE_REPLAYED';

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
  constructor(message = 'Webhook timestamp has expired') {
    super(message, 'WEBHOOK_TIMESTAMP_EXPIRED');
    this.name = 'WebhookTimestampError';
  }
}

export class WebhookNonceError extends WebhookError {
  constructor(message = 'Webhook nonce has been replayed') {
    super(message, 'WEBHOOK_NONCE_REPLAYED');
    this.name = 'WebhookNonceError';
  }
}
