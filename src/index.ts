export {
  buildCanonicalBytes,
  isValidNonce,
  isValidTimestamp,
  NONCE_PATTERN,
} from './canonical.js';
// Deliberately not a WebhookError, and exported from crypto.js rather than errors.js to keep that
// visible: a WebhookError means the request failed to verify and the adapters answer it with 401,
// whereas a runtime with no Web Crypto is the receiver being broken and has to stay a 500.
export { WebCryptoUnavailableError } from './crypto.js';
export type { WebhookErrorCode } from './errors.js';
export {
  WebhookError,
  WebhookNonceError,
  WebhookSignatureError,
  WebhookTimestampError,
} from './errors.js';
export { MAX_SECRETS, normalizeSecrets } from './secrets.js';
export type { ParsedSignature } from './signature.js';
export { formatSignature, parseSignature, SIGNATURE_PATTERN } from './signature.js';
export { signWebhook } from './signer.js';
export type {
  ParseStandardWebhooksSecretOptions,
  SignStandardWebhooksOptions,
  StandardWebhooksHeaders,
  StandardWebhooksSecret,
  VerifyStandardWebhooksOptions,
} from './standard-webhooks.js';
// Standard Webhooks, as a scheme in its own right rather than a mode of this one. The adapters do
// not gain a flag for it: one endpoint speaks one scheme, and a boolean that swapped which headers
// they read would have given `secrets` two meanings - raw bytes here, base64 there - and silently
// dropped the replay protection the Standard Webhooks scheme has no field for. The Web and Hono
// adapters, which do speak both, follow the same rule: one function per scheme, never a switch.
// buildStandardWebhooksBytes stays internal for the same reason buildCanonicalString does: it is
// the shape of the signed value, useful for tests and for showing what was signed, and its output
// is not something a caller should be handing to an HMAC themselves.
export {
  MAX_SIGNATURE_ENTRIES,
  parseStandardWebhooksSecret,
  signStandardWebhooks,
  verifyStandardWebhooks,
} from './standard-webhooks.js';
export type {
  SignWebhookOptions,
  SignWebhookResult,
  VerifyWebhookOptions,
  VerifyWebhookResult,
  WebhookPayload,
  WebhookSecret,
} from './types.js';
export { DEFAULT_TOLERANCE_SECONDS, SIGNATURE_VERSION } from './types.js';
export { verifyWebhook } from './verifier.js';
