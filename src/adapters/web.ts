import type { RequestCheck, RequestFailureStatus } from './request.js';
import {
  type VerifyStandardWebhooksRequestOptions,
  type VerifyWebhookRequestOptions,
  checkStandardWebhooksRequest,
  checkWebhookRequest,
} from './request.js';

export type { AdapterOptions } from './shared.js';
export type {
  RequestFailureStatus,
  VerifyStandardWebhooksRequestOptions,
  VerifyWebhookRequestOptions,
} from './request.js';

/**
 * `ok: false` carries a ready `Response` with the generic JSON body, so a handler can return it as
 * it is. `error` is what failed, for logging; it is also what `onError` received, unless that was
 * not an Error. Never put it in a response. It is non-enumerable so `JSON.stringify` skips it.
 */
export type WebhookRequestResult =
  | { ok: true; payload: Uint8Array }
  | { ok: false; status: RequestFailureStatus; error: Error; response: Response };

function toResult(check: RequestCheck): WebhookRequestResult {
  if (check.ok) {
    return check;
  }
  const result = {
    ok: false as const,
    status: check.status,
    response: Response.json(check.body, { status: check.status }),
  };
  // Non-enumerable, so a handler that serialises the whole result cannot put the error's code and
  // name on the wire: that would hand back the distinction the uniform 401 exists to remove.
  Object.defineProperty(result, 'error', { value: check.error, enumerable: false });
  return result as typeof result & { error: Error };
}

/**
 * Verifies a Standard Webhooks request on any runtime with the Fetch API: Next.js route handlers,
 * Hono, Cloudflare Workers, Deno, Bun. Reads the body once, as bytes, and hands those bytes back on
 * success, so parse them yourself rather than reading the request again.
 *
 * A body that something has already read is a 500 that names `request.clone()`: the signed bytes
 * are gone and no amount of retrying by the sender brings them back.
 */
export async function verifyStandardWebhooksRequest(
  request: Request,
  options: VerifyStandardWebhooksRequestOptions,
): Promise<WebhookRequestResult> {
  return toResult(await checkStandardWebhooksRequest(request, options));
}

/**
 * Verifies a request signed with this package's own scheme (`x-webhook-*` headers, nonce replay
 * protection). Same contract as `verifyStandardWebhooksRequest`, plus the 400 the other adapters
 * give for a missing header.
 */
export async function verifyWebhookRequest(
  request: Request,
  options: VerifyWebhookRequestOptions,
): Promise<WebhookRequestResult> {
  return toResult(await checkWebhookRequest(request, options));
}
