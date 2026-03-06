import { verifyWebhook } from '../verifier.js';
import type { AdapterOptions } from './shared.js';
import { extractHeaders, getHeaderNames, mapErrorToStatus } from './shared.js';

export type { AdapterOptions } from './shared.js';

export const WEBHOOK_OPTIONS = Symbol('WEBHOOK_OPTIONS');

interface ExecutionContext {
  switchToHttp(): HttpContext;
}

interface HttpContext {
  getRequest(): WebhookRequest;
}

interface WebhookRequest {
  headers: Record<string, string | string[] | undefined>;
  body: Buffer | string | unknown;
  webhookVerified?: boolean;
}

export class HttpException extends Error {
  readonly status: number;
  readonly response: string | Record<string, unknown>;

  constructor(response: string | Record<string, unknown>, status: number) {
    super(typeof response === 'string' ? response : JSON.stringify(response));
    this.status = status;
    this.response = response;
  }

  getStatus(): number {
    return this.status;
  }

  getResponse(): string | Record<string, unknown> {
    return this.response;
  }
}

export class WebhookGuard {
  private readonly options: AdapterOptions;

  constructor(options: AdapterOptions) {
    this.options = options;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const headerNames = getHeaderNames(this.options);

    const headerResult = extractHeaders(headerNames, (name) => {
      const val = request.headers[name];
      return Array.isArray(val) ? val[0] : val;
    });

    if ('missing' in headerResult) {
      throw new HttpException({ error: `Missing required header: ${headerResult.missing}` }, 400);
    }

    const raw = request.body;
    const payload = Buffer.isBuffer(raw)
      ? raw.toString('utf-8')
      : typeof raw === 'string'
        ? raw
        : JSON.stringify(raw);

    try {
      await verifyWebhook({
        secret: this.options.secret,
        payload,
        signature: headerResult.signature,
        timestamp: headerResult.timestamp,
        nonce: headerResult.nonce,
        tolerance: this.options.tolerance,
        nonceValidator: this.options.nonceValidator,
      });
      request.webhookVerified = true;
      return true;
    } catch (error: unknown) {
      if (this.options.onError) {
        this.options.onError(error);
      }
      const status = mapErrorToStatus(error);
      const message = error instanceof Error ? error.message : 'Internal server error';
      throw new HttpException({ error: message }, status);
    }
  }
}

export interface WebhookModuleOptions extends AdapterOptions {}

// biome-ignore lint/complexity/noStaticOnlyClass: NestJS module pattern requires a class with static forRoot()
export class WebhookModule {
  static forRoot(options: WebhookModuleOptions): {
    module: typeof WebhookModule;
    providers: Array<{ provide: symbol; useValue: AdapterOptions } | typeof WebhookGuard>;
    exports: Array<symbol | typeof WebhookGuard>;
  } {
    return {
      module: WebhookModule,
      providers: [
        {
          provide: WEBHOOK_OPTIONS,
          useValue: options,
        },
        WebhookGuard,
      ],
      exports: [WEBHOOK_OPTIONS, WebhookGuard],
    };
  }
}
