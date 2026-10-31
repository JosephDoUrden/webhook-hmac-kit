import type { RequestCheck, RequestFailureStatus } from './request.js';
import {
  checkStandardWebhooksRequest,
  checkWebhookRequest,
  type VerifyStandardWebhooksRequestOptions,
  type VerifyWebhookRequestOptions,
} from './request.js';

export type {
  VerifyStandardWebhooksRequestOptions,
  VerifyWebhookRequestOptions,
} from './request.js';
export type { AdapterOptions } from './shared.js';

/**
 * What the middleware puts on the context. Pass it to `new Hono<{ Variables: WebhookVariables }>()`
 * and `c.get('webhookPayload')` is typed as the verified body bytes.
 */
export type WebhookVariables = {
  webhookPayload: Uint8Array;
};

/** The parts of a Hono Context the middleware uses, typed structurally so hono is not a dependency. */
interface HonoContext {
  req: { raw: Request };
  set(key: 'webhookPayload', value: Uint8Array): void;
  json(body: { error: string }, status: RequestFailureStatus): Response;
}

type Next = () => Promise<void>;

type HonoMiddleware = (c: HonoContext, next: Next) => Promise<Response | undefined>;

function middleware(check: (request: Request) => Promise<RequestCheck>): HonoMiddleware {
  return async (c, next) => {
    const result = await check(c.req.raw);
    if (!result.ok) {
      // c.json rather than a fresh Response, so headers set by earlier middleware survive.
      return c.json(result.body, result.status);
    }
    c.set('webhookPayload', result.payload);
    // Outside any catch: a throw from the route belongs to Hono's error handling, not to onError.
    await next();
    return undefined;
  };
}

/**
 * Verifies a Standard Webhooks request before the route runs. The body is read here, once, so
 * the route takes the bytes from `c.get('webhookPayload')` instead of `c.req.json()`.
 */
export function standardWebhooksVerifier(
  options: VerifyStandardWebhooksRequestOptions,
): HonoMiddleware {
  return middleware((request) => checkStandardWebhooksRequest(request, options));
}

/** The same, for this package's own scheme (`x-webhook-*` headers, nonce replay protection). */
export function webhookVerifier(options: VerifyWebhookRequestOptions): HonoMiddleware {
  return middleware((request) => checkWebhookRequest(request, options));
}
