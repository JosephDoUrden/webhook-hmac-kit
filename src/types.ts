export const DEFAULT_TOLERANCE_SECONDS = 300;

/** The only signature scheme this version of the library emits or accepts. */
export const SIGNATURE_VERSION = 'v2';

export interface SignWebhookOptions {
  secret: string;
  /** Exact bytes that will go on the wire. Never a re-serialized object. */
  payload: string;
  /** Unix seconds, non-negative integer. */
  timestamp: number;
  /** Must match `^[A-Za-z0-9_-]{1,64}$`. */
  nonce: string;
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
