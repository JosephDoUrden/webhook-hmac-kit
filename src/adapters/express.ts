import type { WebhookPayload } from '../types.js';
import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import {
  extractHeaders,
  getHeaderNames,
  mapErrorToBody,
  mapErrorToStatus,
  reportError,
  resolveRawBody,
} from './shared.js';

export type { AdapterOptions } from './shared.js';

interface ExpressRequest {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  webhookVerified?: boolean;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

type NextFunction = (err?: unknown) => void;

type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;

/**
 * Mount after `express.raw()` with a `type` that matches the webhook content type, or any parser
 * that leaves `req.body` as a Buffer or string. If a JSON parser has already run on the route the
 * middleware throws a configuration error rather than verifying a re-serialized body.
 */
export function webhookVerifier(options: AdapterOptions): ExpressMiddleware {
  const headerNames = getHeaderNames(options);

  return (req, res, next) => {
    const fail = (error: unknown) => {
      reportError(options, error);
      const status = mapErrorToStatus(error);
      const body = mapErrorToBody(error);
      res.status(status).json(body);
    };

    const headerResult = extractHeaders(headerNames, (name) => req.headers[name]);

    if ('invalid' in headerResult) {
      res.status(400).json({ error: headerResult.invalid });
      return;
    }

    // Throws synchronously on a parsed body: a misconfigured route, not a bad request. It goes
    // through the same handler as a verification failure so onError hears about it, and keeps its
    // own 500 rather than being disguised as a rejected signature.
    let payload: WebhookPayload;
    try {
      payload = resolveRawBody(req);
    } catch (error: unknown) {
      fail(error);
      return;
    }

    verifyWebhook({
      secrets: options.secrets,
      payload,
      signature: headerResult.signature,
      timestamp: headerResult.timestamp,
      nonce: headerResult.nonce,
      tolerance: options.tolerance,
      nonceValidator: options.nonceValidator,
    })
      // Two arguments, not .then().catch(): next() runs the rest of the route, and with a single
      // catch a synchronous throw from the handler downstream arrived here as though the webhook
      // had failed to verify. onError was handed an unrelated error, a second response was written
      // over the one the handler may already have sent, and Express's own error middleware never
      // saw it. A throw from next() belongs on the error path Express provides for it.
      .then(() => {
        req.webhookVerified = true;
        next();
      }, fail)
      .catch(next);
  };
}
