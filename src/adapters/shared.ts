import {
  WebhookError,
  WebhookNonceError,
  WebhookSignatureError,
  WebhookTimestampError,
} from '../errors.js';

export const DEFAULT_SIGNATURE_HEADER = 'x-webhook-signature';
export const DEFAULT_TIMESTAMP_HEADER = 'x-webhook-timestamp';
export const DEFAULT_NONCE_HEADER = 'x-webhook-nonce';

export interface AdapterOptions {
  secret: string;
  tolerance?: number | undefined;
  nonceValidator?: ((nonce: string) => Promise<boolean>) | undefined;
  signatureHeader?: string | undefined;
  timestampHeader?: string | undefined;
  nonceHeader?: string | undefined;
  onError?: ((error: unknown) => void) | undefined;
}

export interface AdapterHeaders {
  signatureHeader: string;
  timestampHeader: string;
  nonceHeader: string;
}

export function getHeaderNames(options: AdapterOptions): AdapterHeaders {
  return {
    signatureHeader: options.signatureHeader ?? DEFAULT_SIGNATURE_HEADER,
    timestampHeader: options.timestampHeader ?? DEFAULT_TIMESTAMP_HEADER,
    nonceHeader: options.nonceHeader ?? DEFAULT_NONCE_HEADER,
  };
}

export function extractHeaders(
  headers: AdapterHeaders,
  getter: (name: string) => string | undefined,
): { signature: string; timestamp: number; nonce: string } | { missing: string } {
  const signature = getter(headers.signatureHeader);
  if (!signature) {
    return { missing: headers.signatureHeader };
  }

  const timestampRaw = getter(headers.timestampHeader);
  if (!timestampRaw) {
    return { missing: headers.timestampHeader };
  }

  const nonce = getter(headers.nonceHeader);
  if (!nonce) {
    return { missing: headers.nonceHeader };
  }

  const timestamp = Number(timestampRaw);

  return { signature, timestamp, nonce };
}

export function mapErrorToStatus(error: unknown): number {
  if (error instanceof WebhookSignatureError) return 401;
  if (error instanceof WebhookTimestampError) return 400;
  if (error instanceof WebhookNonceError) return 409;
  return 500;
}

export function mapErrorToBody(error: unknown): { error: string; code?: string } {
  if (error instanceof WebhookError) {
    return { error: error.message, code: error.code };
  }
  return { error: 'Internal server error' };
}
