import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import { extractHeaders, getHeaderNames, mapErrorToBody, mapErrorToStatus } from './shared.js';

export type { AdapterOptions } from './shared.js';

interface ExpressRequest {
  body: Buffer | string;
  headers: Record<string, string | string[] | undefined>;
  webhookVerified?: boolean;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

type NextFunction = (err?: unknown) => void;

type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;

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

    const payload = Buffer.isBuffer(req.body) ? req.body.toString('utf-8') : req.body;

    verifyWebhook({
      secret: options.secret,
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
