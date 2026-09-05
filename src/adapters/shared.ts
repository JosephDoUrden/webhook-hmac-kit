import { WebhookError } from '../errors.js';
import type { WebhookPayload, WebhookSecret } from '../types.js';

export const DEFAULT_SIGNATURE_HEADER = 'x-webhook-signature';
export const DEFAULT_TIMESTAMP_HEADER = 'x-webhook-timestamp';
export const DEFAULT_NONCE_HEADER = 'x-webhook-nonce';

export interface AdapterOptions {
  secrets: WebhookSecret | WebhookSecret[];
  tolerance?: number | undefined;
  nonceValidator?: ((nonce: string) => Promise<boolean>) | undefined;
  signatureHeader?: string | undefined;
  timestampHeader?: string | undefined;
  nonceHeader?: string | undefined;
  /**
   * Receives the underlying error (WebhookSignatureError, WebhookTimestampError, WebhookNonceError
   * or anything the nonce validator threw). This is the only place the failure reason is exposed;
   * the HTTP response is deliberately generic. Log it here.
   */
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

/**
 * Decimal digits with no leading zeros, so the number the sender signed is spelled the same way as
 * the header it sent. Number() would also accept '1e9', '0x10' and '1.5'; '000{ts}' parses to the
 * same number as '{ts}' while being different bytes, which leaves anything downstream that logs or
 * dedupes on the raw header looking at a value that was never authenticated.
 */
export const TIMESTAMP_PATTERN = /^(0|[1-9]\d*)$/;

/**
 * Node folds duplicate request headers into one comma-joined string, which fails closed against the
 * signature grammar. An array means some layer kept them apart instead, and taking the first entry
 * would drop the rest without saying so, so more than one value is refused.
 */
function readHeader(
  getter: (name: string) => string | string[] | undefined,
  name: string,
): { value: string } | { invalid: string } {
  const raw = getter(name);
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (Array.isArray(raw) && raw.length > 1) {
    return { invalid: `Duplicate header: ${name}` };
  }
  return value ? { value } : { invalid: `Missing required header: ${name}` };
}

export function extractHeaders(
  headers: AdapterHeaders,
  getter: (name: string) => string | string[] | undefined,
): { signature: string; timestamp: number; nonce: string } | { invalid: string } {
  const signature = readHeader(getter, headers.signatureHeader);
  if ('invalid' in signature) {
    return signature;
  }

  const timestampRaw = readHeader(getter, headers.timestampHeader);
  if ('invalid' in timestampRaw) {
    return timestampRaw;
  }

  const nonce = readHeader(getter, headers.nonceHeader);
  if ('invalid' in nonce) {
    return nonce;
  }

  const timestamp = TIMESTAMP_PATTERN.test(timestampRaw.value)
    ? Number(timestampRaw.value)
    : Number.NaN;

  return { signature: signature.value, timestamp, nonce: nonce.value };
}

/**
 * Picks the bytes to verify from what the framework hands us.
 *
 * The signature covers the exact bytes the sender put on the wire. Once a body parser has turned
 * them into an object there is no way back: JSON.stringify changes whitespace and may change key
 * order, so verification would fail for every request and look like a bad secret. That is a
 * configuration problem, and it is reported as one instead of being papered over.
 *
 * A Buffer is handed on as it is. Decoding it to a string first would collapse every byte sequence
 * that is not valid UTF-8 onto the same replacement characters, and two different bodies would
 * share one signature.
 */
export function resolveRawBody(request: { rawBody?: unknown; body?: unknown }): WebhookPayload {
  const raw = request.rawBody ?? request.body;
  if (Buffer.isBuffer(raw)) {
    return raw;
  }
  if (typeof raw === 'string') {
    return raw;
  }
  throw new Error(
    'Webhook verification needs the raw body, but the request body has already been parsed. ' +
      'Configure a raw body parser for this route (for example express.raw(), Fastify rawBody, ' +
      'or NestJS rawBody: true) so the exact bytes that were signed are available.',
  );
}

/**
 * Every verification failure is a 401. Distinct status codes (400 for an expired timestamp, 409 for
 * a replayed nonce) would tell an unauthenticated caller that its signature was accepted and only
 * a later check failed, which confirms the secret is still live. The reason is available through
 * `onError`; it does not go on the wire.
 */
export function mapErrorToStatus(error: unknown): number {
  if (error instanceof WebhookError) return 401;
  return 500;
}

/** See mapErrorToStatus: one body for every verification failure, no code, no reason. */
export function mapErrorToBody(error: unknown): { error: string } {
  if (error instanceof WebhookError) {
    return { error: 'Webhook verification failed' };
  }
  return { error: 'Internal server error' };
}
