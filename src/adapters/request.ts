import type { StandardWebhooksSecret } from '../standard-webhooks.js';
import { verifyStandardWebhooks } from '../standard-webhooks.js';
import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import {
  extractHeaders,
  getHeaderNames,
  mapErrorToBody,
  mapErrorToStatus,
  reportError,
} from './shared.js';

/**
 * The verification core shared by the Web and Hono adapters. Internal: it answers with a status
 * and a body, and each adapter turns those into whatever its framework writes to the wire.
 */

export interface VerifyWebhookRequestOptions extends AdapterOptions {
  /**
   * Unix seconds to measure the tolerance window from. Defaults to the system clock. Never derive
   * it from the request or pin it in production; that removes the replay window.
   */
  now?: number | undefined;
}

export interface VerifyStandardWebhooksRequestOptions {
  /** Every secret that is currently live, base64 with or without `whsec_`, or the key bytes. */
  secrets: StandardWebhooksSecret | StandardWebhooksSecret[];
  /** Seconds either side of now. Defaults to 300. */
  tolerance?: number | undefined;
  /** See `VerifyWebhookRequestOptions.now`. */
  now?: number | undefined;
  /**
   * Receives the underlying error. This is the only place the failure reason is exposed; the
   * response is deliberately generic. Log it here.
   */
  onError?: ((error: unknown) => void) | undefined;
}

export type RequestFailureStatus = 400 | 401 | 500;

export type RequestCheck =
  | { ok: true; payload: Uint8Array }
  | { ok: false; status: RequestFailureStatus; error: Error; body: { error: string } };

const SW_HEADERS = ['webhook-id', 'webhook-timestamp', 'webhook-signature'] as const;

/**
 * A Request body is a stream and can be read once. If something upstream already read it, the
 * bytes that were signed are gone, which is a misconfigured route rather than a bad request, and
 * it is reported the way resolveRawBody reports a parsed body: as a 500 that names the fix.
 */
function bodyAlreadyRead(): Error {
  return new Error(
    'Webhook verification needs the raw body, but this Request has already been read. ' +
      'Verify before anything else reads the body, or pass request.clone() taken before it was read.',
  );
}

function fail(options: Pick<AdapterOptions, 'onError'>, error: unknown) {
  reportError(options, error);
  // verifyWebhook already wraps whatever a nonce validator throws, so nothing known reaches here
  // that is not an Error. The result promises one regardless; onError still gets the original.
  const wrapped =
    error instanceof Error
      ? error
      : new Error('Webhook verification failed with a non-Error value', { cause: error });
  return {
    ok: false as const,
    status: mapErrorToStatus(error),
    error: wrapped,
    body: mapErrorToBody(error),
  };
}

/** Bytes as they arrived. Never decoded to text: two different bodies would share a signature. */
async function readBody(request: Request): Promise<Uint8Array> {
  return new Uint8Array(await request.arrayBuffer());
}

export async function checkWebhookRequest(
  request: Request,
  options: VerifyWebhookRequestOptions,
): Promise<RequestCheck> {
  if (request.bodyUsed) {
    return fail(options, bodyAlreadyRead());
  }

  // Fetch Headers fold a repeated header into one "a, b" string rather than an array, so the
  // duplicate check in extractHeaders never fires here. The folded value fails the timestamp,
  // nonce or signature grammar instead, and that is a 401 like any other failed verification.
  const headerResult = extractHeaders(
    getHeaderNames(options),
    (name) => request.headers.get(name) ?? undefined,
  );
  if ('invalid' in headerResult) {
    // The same 400 the Express, Fastify and Nest adapters give, and like them it is not reported:
    // the request is malformed, it did not fail to verify.
    return {
      ok: false,
      status: 400,
      error: new Error(headerResult.invalid),
      body: { error: headerResult.invalid },
    };
  }

  try {
    const payload = await readBody(request);
    await verifyWebhook({
      secrets: options.secrets,
      payload,
      signature: headerResult.signature,
      timestamp: headerResult.timestamp,
      nonce: headerResult.nonce,
      tolerance: options.tolerance,
      nonceValidator: options.nonceValidator,
      now: options.now,
    });
    return { ok: true, payload };
  } catch (error: unknown) {
    return fail(options, error);
  }
}

/**
 * No 400 here. A missing Standard Webhooks header is a request that failed to verify, which the
 * core reports as a WebhookSignatureError and every adapter answers with 401.
 */
export async function checkStandardWebhooksRequest(
  request: Request,
  options: VerifyStandardWebhooksRequestOptions,
): Promise<RequestCheck> {
  if (request.bodyUsed) {
    return fail(options, bodyAlreadyRead());
  }

  // Only the three names the scheme defines. Fetch Headers join repeated values with ", ", so in a
  // folded signature header the last entry of every header value except the final one keeps the
  // comma, fails strict base64 and is skipped like any other malformed entry; the rest still parse.
  const headers: Record<string, string | undefined> = {};
  for (const name of SW_HEADERS) {
    headers[name] = request.headers.get(name) ?? undefined;
  }

  try {
    const payload = await readBody(request);
    await verifyStandardWebhooks({
      secrets: options.secrets,
      headers,
      payload,
      tolerance: options.tolerance,
      now: options.now,
    });
    return { ok: true, payload };
  } catch (error: unknown) {
    return fail(options, error);
  }
}
