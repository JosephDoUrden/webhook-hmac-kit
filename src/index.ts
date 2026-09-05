export {
  NONCE_PATTERN,
  buildCanonicalBytes,
  isValidNonce,
  isValidTimestamp,
} from './canonical.js';
// Deliberately not a WebhookError, and exported from crypto.js rather than errors.js to keep that
// visible: a WebhookError means the request failed to verify and the adapters answer it with 401,
// whereas a runtime with no Web Crypto is the receiver being broken and has to stay a 500.
export { WebCryptoUnavailableError } from './crypto.js';
export {
  WebhookError,
  WebhookSignatureError,
  WebhookTimestampError,
  WebhookNonceError,
} from './errors.js';
export type { WebhookErrorCode } from './errors.js';
export { MAX_SECRETS, normalizeSecrets } from './secrets.js';
export { signWebhook } from './signer.js';
export { SIGNATURE_PATTERN, formatSignature, parseSignature } from './signature.js';
export type { ParsedSignature } from './signature.js';
export { DEFAULT_TOLERANCE_SECONDS, SIGNATURE_VERSION } from './types.js';
export type {
  SignWebhookOptions,
  SignWebhookResult,
  VerifyWebhookOptions,
  VerifyWebhookResult,
  WebhookPayload,
  WebhookSecret,
} from './types.js';
export { verifyWebhook } from './verifier.js';
