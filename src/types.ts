export const DEFAULT_TOLERANCE_SECONDS = 300;
export const DEFAULT_VERSION = 'v1';

export interface SignWebhookOptions {
  secret: string;
  payload: string;
  timestamp: number;
  nonce: string;
  version?: string | undefined;
}

export interface SignWebhookResult {
  signature: string;
}

export interface VerifyWebhookOptions {
  secret: string;
  payload: string;
  signature: string;
  timestamp: number;
  nonce: string;
  tolerance?: number | undefined;
  nonceValidator?: ((nonce: string) => Promise<boolean>) | undefined;
}

export interface VerifyWebhookResult {
  valid: true;
}
