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

  // An async hook that has already answered must return the reply. Without it Fastify does not
  // learn the response went out and carries on into the route handler, which runs its side effects
  // and only then fails with FST_ERR_REP_ALREADY_SENT.
  fastify.decorate(
    'verifyWebhook',
    async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
      const headerResult = extractHeaders(headerNames, (name) => request.headers[name]);

      if ('invalid' in headerResult) {
        return reply.code(400).send({ error: headerResult.invalid });
      }

      // Fastify parses JSON by default, so `request.body` is usually an object. The raw bytes
      // come from `request.rawBody` (fastify-raw-body or an equivalent content-type parser).
      // Without either this throws a configuration error rather than verifying a re-serialized
      // body.
      const payload = resolveRawBody(request);

      try {
        await verifyWebhook({
          secrets: options.secrets,
          payload,
          signature: headerResult.signature,
          timestamp: headerResult.timestamp,
          nonce: headerResult.nonce,
          tolerance: options.tolerance,
          nonceValidator: options.nonceValidator,
        });
        request.webhookVerified = true;
        return undefined;
      } catch (error: unknown) {
        if (options.onError) {
          options.onError(error);
        }
        const status = mapErrorToStatus(error);
        const body = mapErrorToBody(error);
        return reply.code(status).send(body);
      }
    },
  );

  done();
}

// Mark as a plugin that doesn't need encapsulation
(webhookPlugin as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true;
