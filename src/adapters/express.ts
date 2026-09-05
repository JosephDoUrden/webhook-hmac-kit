import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import {
  extractHeaders,
  getHeaderNames,
  mapErrorToBody,
  mapErrorToStatus,
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
    const headerResult = extractHeaders(headerNames, (name) => {
      const val = req.headers[name];
      return Array.isArray(val) ? val[0] : val;
    });

    if ('missing' in headerResult) {
      const status = 400;
      res.status(status).json({ error: `Missing required header: ${headerResult.missing}` });
      return;
    }

    // Throws synchronously on a parsed body: a misconfigured route, not a bad request.
    const payload = resolveRawBody(req);

    verifyWebhook({
      secrets: options.secrets,
      payload,
      signature: headerResult.signature,
      timestamp: headerResult.timestamp,
      nonce: headerResult.nonce,
      tolerance: options.tolerance,
      nonceValidator: options.nonceValidator,
    })
      .then(() => {
        req.webhookVerified = true;
        next();
      })
      .catch((error: unknown) => {
        if (options.onError) {
          options.onError(error);
        }
        const status = mapErrorToStatus(error);
        const body = mapErrorToBody(error);
        res.status(status).json(body);
      });
  };
}
