import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import { extractHeaders, getHeaderNames, mapErrorToBody, mapErrorToStatus } from './shared.js';

export type { AdapterOptions } from './shared.js';

interface FastifyRequest {
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
  rawBody?: Buffer | string | undefined;
  webhookVerified?: boolean;
}

interface FastifyReply {
  code(statusCode: number): FastifyReply;
  send(payload: unknown): FastifyReply;
}

interface FastifyInstance {
  decorate(name: string, value: unknown): void;
  decorateRequest(name: string, value: unknown): void;
}

type DoneCallback = (err?: Error) => void;

export function webhookPlugin(
  fastify: FastifyInstance,
  options: AdapterOptions,
  done: DoneCallback,
): void {
  const headerNames = getHeaderNames(options);

  fastify.decorateRequest('webhookVerified', false);

  fastify.decorate(
    'verifyWebhook',
    async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const headerResult = extractHeaders(headerNames, (name) => {
        const val = request.headers[name];
        return Array.isArray(val) ? val[0] : val;
      });

      if ('missing' in headerResult) {
        reply.code(400).send({ error: `Missing required header: ${headerResult.missing}` });
        return;
      }

      const raw = request.rawBody ?? request.body;
      const payload = Buffer.isBuffer(raw)
        ? raw.toString('utf-8')
        : typeof raw === 'string'
          ? raw
          : JSON.stringify(raw);

      try {
        await verifyWebhook({
          secret: options.secret,
          payload,
          signature: headerResult.signature,
          timestamp: headerResult.timestamp,
          nonce: headerResult.nonce,
          tolerance: options.tolerance,
          nonceValidator: options.nonceValidator,
        });
        request.webhookVerified = true;
      } catch (error: unknown) {
        if (options.onError) {
          options.onError(error);
        }
        const status = mapErrorToStatus(error);
        const body = mapErrorToBody(error);
        reply.code(status).send(body);
      }
    },
  );

  done();
}

// Mark as a plugin that doesn't need encapsulation
(webhookPlugin as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true;
