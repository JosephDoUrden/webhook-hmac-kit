import { WebhookError } from '../errors.js';

export const DEFAULT_SIGNATURE_HEADER = 'x-webhook-signature';
export const DEFAULT_TIMESTAMP_HEADER = 'x-webhook-timestamp';
export const DEFAULT_NONCE_HEADER = 'x-webhook-nonce';

export interface AdapterOptions {
  secrets: string | string[];
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

  // Decimal digits only. Number() would also accept '1e9', '0x10' and '1.5', and the verifier's
  // strict-integer check is easier to reason about when the header parser is strict too.
  const timestamp = /^\d+$/.test(timestampRaw) ? Number(timestampRaw) : Number.NaN;

  return { signature, timestamp, nonce };
}

/**
 * Picks the bytes to verify from what the framework hands us.
 *
 * The signature covers the exact bytes the sender put on the wire. Once a body parser has turned
 * them into an object there is no way back: JSON.stringify changes whitespace and may change key
 * order, so verification would fail for every request and look like a bad secret. That is a
 * configuration problem, and it is reported as one instead of being papered over.
 */
export function resolveRawBody(request: { rawBody?: unknown; body?: unknown }): string {
  const raw = request.rawBody ?? request.body;
  if (Buffer.isBuffer(raw)) {
    return raw.toString('utf-8');
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
