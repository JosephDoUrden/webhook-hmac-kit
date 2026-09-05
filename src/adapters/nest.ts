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

export const WEBHOOK_OPTIONS = Symbol('WEBHOOK_OPTIONS');

interface ExecutionContext {
  switchToHttp(): HttpContext;
}

interface HttpContext {
  getRequest(): WebhookRequest;
}

interface WebhookRequest {
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
  /** Populated by NestJS when the app is created with `rawBody: true`. */
  rawBody?: Buffer | string | undefined;
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

    const headerResult = extractHeaders(headerNames, (name) => request.headers[name]);

    if ('invalid' in headerResult) {
      throw new HttpException({ error: headerResult.invalid }, 400);
    }

    // Create the app with `NestFactory.create(AppModule, { rawBody: true })` so `request.rawBody`
    // carries the exact bytes. A parsed body with no rawBody is a configuration error and is
    // thrown as a plain Error, not an HttpException, so it surfaces as a 500 in the logs.
    const payload = resolveRawBody(request);

    try {
      await verifyWebhook({
        secrets: this.options.secrets,
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
      reportError(this.options, error);
      throw new HttpException(mapErrorToBody(error), mapErrorToStatus(error));
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
