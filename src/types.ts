export const DEFAULT_TOLERANCE_SECONDS = 300;

/** The only signature scheme this version of the library emits or accepts. */
export const SIGNATURE_VERSION = 'v2';

export interface SignWebhookOptions {
  /** One secret, or a list where the first entry is the one used to sign. */
  secrets: string | string[];
  /** Exact bytes that will go on the wire. Never a re-serialized object. */
  payload: string;
  /** Unix seconds, non-negative integer. */
  timestamp: number;
  /** Must match `^[A-Za-z0-9_-]{1,64}$`. */
  nonce: string;
}

export interface SignWebhookResult {
  /** Wire form, `v2={hex}`. Put this in the signature header as is. */
  signature: string;
}

export interface VerifyWebhookOptions {
  /** One secret, or every secret that is currently live. A signature made with any of them is accepted. */
  secrets: string | string[];
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
