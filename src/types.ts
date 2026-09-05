export const DEFAULT_TOLERANCE_SECONDS = 300;

/** The only signature scheme this version of the library emits or accepts. */
export const SIGNATURE_VERSION = 'v2';

/**
 * Key material for HMAC-SHA256. A string is UTF-8 encoded; pass bytes for a key that is not UTF-8
 * text, because UTF-8 encoding maps every unpaired surrogate onto the same three bytes.
 */
export type WebhookSecret = string | Uint8Array;

/**
 * The exact bytes that go on the wire. A string is UTF-8 encoded, which is what a JSON body wants;
 * anything that is not UTF-8 text has to be passed as bytes to keep its identity.
 */
export type WebhookPayload = string | Uint8Array;

export interface SignWebhookOptions {
  /** One secret, or a list where the first entry is the one used to sign. */
  secrets: WebhookSecret | WebhookSecret[];
  /** Exact bytes that will go on the wire. Never a re-serialized object. */
  payload: WebhookPayload;
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
  secrets: WebhookSecret | WebhookSecret[];
  payload: WebhookPayload;
  signature: string;
  timestamp: number;
  nonce: string;
  tolerance?: number | undefined;
  nonceValidator?: ((nonce: string) => Promise<boolean>) | undefined;
}

export interface VerifyWebhookResult {
  valid: true;
}
