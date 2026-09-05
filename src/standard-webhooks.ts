/**
 * Standard Webhooks (standardwebhooks.com), as a separate scheme sitting beside this package's own.
 *
 * Additive and self-contained. It shares the byte helpers and the HMAC layer with the v2 scheme and
 * nothing else: a separate canonical builder, a separate secret type, a separate signature grammar,
 * a separate parser. The v2 header and canonical value are unchanged by anything in this file.
 *
 * ## The encoding is not injective, and that is theirs, not ours
 *
 * The signed value is `{messageId}.{timestamp}.{payload}` and nothing constrains the message id, so
 * an id that holds a dot and a run of digits re-splits into a different (id, timestamp, payload)
 * triple carrying the same signature. `msg_1.1700000000` at timestamp 1700000300 signs the same
 * bytes as `msg_1` at timestamp 1700000000 with `1700000300.` in front of the payload.
 *
 * We do not fix this. The fix would be domain separation or an id grammar, and either one changes
 * the bytes that get signed, which means emitting signatures no conforming receiver accepts and
 * refusing ones every conforming sender emits. Conformance is the whole point of this module, so
 * the ambiguity is documented and pinned by a test instead. The consequence for callers is one
 * sentence: **`webhook-id` is not a trust boundary.** It is not authenticated in any useful sense,
 * so it must not be a replay-cache key, an idempotency key that guards a state change, or an
 * authorisation input. This package's own scheme puts a dot-free nonce behind a strict-integer
 * timestamp precisely so that its nonce can be all three of those things.
 *
 * ## The two schemes must never share key material
 *
 * `v2.{ts}.{nonce}.{payload}` and a Standard Webhooks message whose id is the literal string `v2`
 * and whose payload is `{nonce}.{payload}` are the same bytes. One key used for both schemes
 * therefore lets a signature minted under one be presented as a valid signature under the other.
 * Domain separation would close it and conformance forbids domain separation, so the rule is
 * operational: **generate a separate secret for Standard Webhooks and never reuse a v2 secret for
 * it.** A test pins the collision so nobody discovers it the hard way.
 *
 * ## Where this is deliberately narrower or wider than the reference libraries
 *
 * Narrower on send: a payload that is not well-formed UTF-8 is refused, and the signing key has to
 * be inside the spec's stated 24-64 byte range. Wider on receive: any non-empty key is accepted and
 * the payload is HMAC'd as raw bytes. Each of those has its reason written where it is enforced.
 */

import { bytesEqual, concat, fromBase64, toBase64, utf8 } from './bytes.js';
import { isValidTimestamp } from './canonical.js';
import { blindedEqual, hmacSha256 } from './crypto.js';
import { WebhookSignatureError, WebhookTimestampError } from './errors.js';
import { MAX_SECRETS } from './secrets.js';
import { DEFAULT_TOLERANCE_SECONDS } from './types.js';
import type { VerifyWebhookResult, WebhookPayload } from './types.js';

const ID_HEADER = 'webhook-id';
const TIMESTAMP_HEADER = 'webhook-timestamp';
const SIGNATURE_HEADER = 'webhook-signature';
const HEADER_NAMES = [ID_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER];

/** The only signature tag emitted or checked here. Every other tag is skipped: see parseDigests. */
const SIGNATURE_TAG = 'v1';

const SECRET_PREFIX = 'whsec_';

/**
 * A `whsec_` secret once the prefix is off.
 *
 * Standard alphabet only. URL-safe input fails here rather than being re-read, because '-' and '_'
 * are not in this alphabet and a value spelled with them decodes to different key material
 * everywhere in this ecosystem, which is a silently wrong key rather than a loud error.
 */
const SECRET_GRAMMAR = /^[A-Za-z0-9+/]+={0,2}$/;

/** The spec's stated range, in bytes. Enforced when signing only; see parseStandardWebhooksSecret. */
const MIN_SIGNING_KEY_BYTES = 24;
const MAX_SIGNING_KEY_BYTES = 64;

const SHA256_DIGEST_BYTES = 32;

/**
 * How many signature entries a verify will weigh, however many arrive.
 *
 * The entry count is chosen by whoever is calling, and every entry is compared against every
 * configured secret, so without a cap an unauthenticated request buys as much of the receiver's
 * CPU as its header size allows: correct-length junk costs nothing to produce, and 337 entries fit
 * in Node's default 16 KiB header block, which against a 16-key rotation is over five thousand
 * comparisons for one request that was never going to verify. The 32-byte length guard in
 * parseDigests does not help here - it only drops entries that are too short.
 *
 * Set to MAX_SECRETS because it is the same quantity seen from the other end. A conforming sender
 * emits one entry per live key, so the longest legitimate list is the longest legitimate rotation,
 * which this package already caps at 16. Anything past that is refused rather than weighed, and a
 * valid signature sitting beyond the cap is not found - a trade-off, and one no real sender meets.
 */
export const MAX_SIGNATURE_ENTRIES = MAX_SECRETS;

/**
 * A message id we are willing to put our own name to: no dot, because the dot is the field
 * delimiter, and no whitespace, because the signature header is a space-separated list and an id
 * carrying a space reads as two of something.
 */
const UNSIGNABLE_MESSAGE_ID = /[.\s]/;

/**
 * Decimal digits, no leading zeros, and this module's own copy rather than the adapters'.
 *
 * The reference libraries parse this header loosely - `parseInt` in JavaScript, `float` in Python -
 * so `1614265330abc` and `1.5e9` both reach their window check. Strictness on receive is ours to
 * choose and the choice here is the same as everywhere else in this package: the value that gets
 * checked is the value the sender actually signed, so anything downstream that logs or dedupes on
 * the raw header is looking at an authenticated string.
 */
const TIMESTAMP_PATTERN = /^(0|[1-9]\d*)$/;

/** Shared and stateless between calls, because nothing here decodes in streaming mode. */
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Key material for Standard Webhooks.
 *
 * Deliberately not `WebhookSecret`, which has the same TypeScript shape and a different meaning: a
 * string there is raw UTF-8 key material, and a string here is base64 that decodes to the key. One
 * option carrying both readings would make the same configured value mean two different keys
 * depending on which function received it.
 *
 * A `Uint8Array` means the same thing in both: these are the key bytes, no decoding.
 */
export type StandardWebhooksSecret = string | Uint8Array;

/** The three headers, spelled the way the specification spells them: lower case, no prefix. */
export type StandardWebhooksHeaders = {
  'webhook-id': string;
  'webhook-timestamp': string;
  'webhook-signature': string;
};

export interface ParseStandardWebhooksSecretOptions {
  /**
   * `'sign'` additionally enforces the spec's 24-64 byte range. Defaults to `'verify'`, which
   * checks only that the key is not empty.
   *
   * The asymmetry is the point. The range is a statement about keys we generate, and no reference
   * library enforces it at all, so applying it on receive would reject a key that whoever is
   * sending to us already chose and is already signing with - the upstream Python suite has a
   * 23-byte fixture that does exactly that. Applying it on send costs nobody anything.
   */
  usage?: 'sign' | 'verify' | undefined;
}

export interface SignStandardWebhooksOptions {
  /** One secret, or several: one `v1,` entry is emitted per distinct secret, in the order given. */
  secrets: StandardWebhooksSecret | StandardWebhooksSecret[];
  /** The event id. Per-event and stable across retries, unlike this package's per-attempt nonce. */
  messageId: string;
  /** Unix seconds, non-negative integer. */
  timestamp: number;
  /** Exact bytes that will go on the wire. Must be well-formed UTF-8; see assertSignablePayload. */
  payload: WebhookPayload;
}

export interface VerifyStandardWebhooksOptions {
  /** Every secret that is currently live. A signature made with any of them is accepted. */
  secrets: StandardWebhooksSecret | StandardWebhooksSecret[];
  /**
   * The request headers. Names are matched case-insensitively, a single-entry array is unwrapped,
   * more than one value for the same header is refused, and an empty string counts as missing.
   */
  headers: Record<string, string | string[] | undefined>;
  /** The raw body, as bytes wherever it is not text. */
  payload: WebhookPayload;
  /** Seconds either side of now. Defaults to 300, which is what every reference library hard-codes. */
  tolerance?: number | undefined;
}

/**
 * Turns a Standard Webhooks secret into key bytes.
 *
 * A string is base64, with the `whsec_` prefix stripped if it is there. There is no
 * "not prefixed means raw" path, in this implementation or in any of the reference ones: the
 * prefix exists to make the value recognisable, not to select an encoding. A `Uint8Array` is the
 * key itself, copied so a later write by the caller cannot change it underneath a verify.
 *
 * The decode is strict where the reference implementations are not. Python's `b64decode` with
 * `validate=False` drops out-of-alphabet characters, so `not-a-base64-secret!` becomes a twelve
 * byte key nobody chose while Go rejects the same string; a receiver and a sender configured with
 * one literal can end up holding different keys and neither of them finds out. Two closed upstream
 * issues are people who hit the same class of mistake from opposite directions.
 */
export function parseStandardWebhooksSecret(
  secret: StandardWebhooksSecret,
  options: ParseStandardWebhooksSecretOptions = {},
): Uint8Array {
  const bytes = secret instanceof Uint8Array ? Uint8Array.from(secret) : decodeSecret(secret);

  if (bytes.length === 0) {
    throw new TypeError('a Standard Webhooks secret must not be empty');
  }

  if (
    (options.usage ?? 'verify') === 'sign' &&
    (bytes.length < MIN_SIGNING_KEY_BYTES || bytes.length > MAX_SIGNING_KEY_BYTES)
  ) {
    throw new TypeError(
      `a Standard Webhooks signing key must be between ${MIN_SIGNING_KEY_BYTES} and ` +
        `${MAX_SIGNING_KEY_BYTES} bytes (this one decodes to ${bytes.length})`,
    );
  }

  return bytes;
}

function decodeSecret(secret: string): Uint8Array {
  if (typeof secret !== 'string') {
    throw new TypeError('a Standard Webhooks secret must be a string or a Uint8Array');
  }

  const encoded = secret.startsWith(SECRET_PREFIX) ? secret.slice(SECRET_PREFIX.length) : secret;
  if (!SECRET_GRAMMAR.test(encoded) || encoded.length % 4 === 1) {
    throw new TypeError(
      "a Standard Webhooks secret must be standard-alphabet base64, optionally prefixed 'whsec_' " +
        "(no '-', no '_', no whitespace)",
    );
  }

  const bytes = fromBase64(encoded);

  // Belt and braces. fromBase64 allocates exactly this many bytes, so the check can only fire if
  // that decoder is ever swapped for a platform one - and every platform decoder in reach is
  // lenient enough to return a short buffer for input it should have refused.
  const withoutPadding = encoded.replace(/=+$/, '').length;
  if (bytes.length !== (withoutPadding * 6) >> 3) {
    throw new TypeError('a Standard Webhooks secret decoded to an unexpected number of bytes');
  }
  return bytes;
}

/**
 * The bytes Standard Webhooks signs: `{messageId}.{timestamp}.{payload}`.
 *
 * Not `buildCanonicalPrefix`, and not shaped like it. That builder enforces this package's nonce
 * grammar, and a message id is not a nonce: it is per-event rather than per-attempt, stable across
 * retries so a redelivery carries the same one, and legal with a dot in it. Running a real id
 * through the nonce grammar would refuse messages conforming senders emit every day.
 *
 * Which also means the result is not injective. See the note at the top of this file: it is a
 * property of their specification, it cannot be fixed here, and `webhook-id` is not a trust
 * boundary because of it.
 */
export function buildStandardWebhooksBytes(
  messageId: string,
  timestamp: number,
  payload: WebhookPayload,
): Uint8Array {
  if (typeof messageId !== 'string' || messageId.length === 0) {
    throw new TypeError('messageId must be a non-empty string');
  }
  if (!isValidTimestamp(timestamp)) {
    throw new TypeError('timestamp must be a non-negative safe integer (unix seconds)');
  }
  // A template literal stringifies anything, so without this an array, null or a plain object
  // would sign as 'a', 'null' or '[object Object]' and two callers who meant different things
  // would collide.
  if (typeof payload !== 'string' && !(payload instanceof Uint8Array)) {
    throw new TypeError('payload must be a string or a Uint8Array');
  }

  const payloadBytes = typeof payload === 'string' ? utf8(payload) : payload;
  return concat(utf8(`${messageId}.${timestamp}.`), payloadBytes);
}

/**
 * Signs a webhook in the Standard Webhooks scheme and returns the three headers to send.
 *
 * One `v1,<base64>` entry per distinct secret, space-joined, which is their rotation model: the
 * sender emits a signature under every live key and the receiver tries each entry.
 *
 * Deliberately not an `async function`, for the same reason `signWebhook` is not. An async function
 * cannot throw synchronously, so marking this one would turn every argument mistake - an empty
 * secret list, a key outside the spec's range, an id with a dot in it, a payload that is not
 * well-formed UTF-8 - into a rejected promise, and a caller who wrapped the call in `try/catch`
 * would silently stop catching its own misconfiguration.
 */
export function signStandardWebhooks(
  options: SignStandardWebhooksOptions,
): Promise<StandardWebhooksHeaders> {
  const secrets = normalizeStandardWebhooksSecrets(options.secrets, 'sign');
  const { messageId, timestamp, payload } = options;

  assertSignableMessageId(messageId);
  assertSignablePayload(payload);

  const signed = buildStandardWebhooksBytes(messageId, timestamp, payload);

  return Promise.all(secrets.map((secret) => hmacSha256(secret, signed))).then((digests) => ({
    [ID_HEADER]: messageId,
    [TIMESTAMP_HEADER]: String(timestamp),
    [SIGNATURE_HEADER]: digests.map((digest) => `${SIGNATURE_TAG},${toBase64(digest)}`).join(' '),
  }));
}

/**
 * Verifies a Standard Webhooks request. Resolves to `{ valid: true }` or throws a `WebhookError`,
 * the same contract as `verifyWebhook`, so an adapter maps both to the same uniform 401.
 *
 * The payload is HMAC'd as the bytes it arrived in, which is Go's behaviour and the plain reading
 * of the spec. It is not decoded to a string first: that is what the JavaScript and Python
 * reference libraries do, and it collapses every byte sequence that is not valid UTF-8 onto the
 * same replacement characters, so two different bodies would share one signature. A sender that
 * mangled the body before signing it simply fails to verify here, which is the correct outcome
 * rather than a compatibility problem worth reproducing.
 *
 * There is no replay check and no `messageId` validator, on purpose. See the top of this file:
 * their canonical encoding is not injective, so `webhook-id` cannot carry the weight this
 * package's nonce carries.
 */
export async function verifyStandardWebhooks(
  options: VerifyStandardWebhooksOptions,
): Promise<VerifyWebhookResult> {
  const secrets = normalizeStandardWebhooksSecrets(options.secrets, 'verify');

  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  if (!Number.isFinite(tolerance) || tolerance < 0) {
    throw new Error('tolerance must be a non-negative finite number');
  }

  const headers = readHeaders(options.headers);

  // 1. Timestamp (cheapest - no crypto, no I/O). One error class and one message whichever side of
  //    the window it fell on: upstream answers "too old" and "too new" separately, which tells an
  //    unauthenticated caller how far out its clock is before it has proved anything.
  if (!TIMESTAMP_PATTERN.test(headers.timestamp)) {
    throw new WebhookTimestampError(
      'Webhook timestamp must be a non-negative integer',
      'WEBHOOK_TIMESTAMP_INVALID',
    );
  }
  const timestamp = Number(headers.timestamp);
  if (!isValidTimestamp(timestamp)) {
    throw new WebhookTimestampError(
      'Webhook timestamp must be a non-negative integer',
      'WEBHOOK_TIMESTAMP_INVALID',
    );
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > tolerance) {
    throw new WebhookTimestampError();
  }

  // 2. The signature list, before any HMAC work. Two separate guards, and only one of them is
  //    about cost. Anything that does not decode to a 32-byte digest cannot be an HMAC-SHA256
  //    output, so it is dropped rather than compared against one; that alone bounds nothing,
  //    because correct-length junk is free to produce. The cap is what bounds the work, and
  //    MAX_SIGNATURE_ENTRIES says why.
  const presented = parseDigests(headers.signature).slice(0, MAX_SIGNATURE_ENTRIES);
  if (presented.length === 0) {
    throw new WebhookSignatureError('Webhook signature header carries no usable v1 signature');
  }

  // 3. Every secret against every entry, with the results OR-ed at the end. No break out of either
  //    loop: returning early would say which secret and which entry a forgery got closest to.
  const signed = buildStandardWebhooksBytes(headers.id, timestamp, options.payload);
  let matches = 0;
  for (const secret of secrets) {
    const expected = await hmacSha256(secret, signed);
    for (const digest of presented) {
      matches |= (await blindedEqual(expected, digest)) ? 1 : 0;
    }
  }
  if (matches === 0) {
    throw new WebhookSignatureError();
  }

  return { valid: true };
}

/**
 * The same rotation and hygiene rules as `normalizeSecrets`, over the other secret type.
 *
 * Not a call into that function with a pre-decoded list, because the failure messages would then
 * describe the wrong thing, and not a shared implementation, because the two secret types differ
 * in exactly the place a shared one would have to branch.
 */
function normalizeStandardWebhooksSecrets(
  secrets: StandardWebhooksSecret | StandardWebhooksSecret[],
  usage: 'sign' | 'verify',
): [Uint8Array, ...Uint8Array[]] {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  if (list.length === 0) {
    throw new Error('secrets must not be empty');
  }

  // A repeated secret costs an HMAC per request and an extra signature on the wire, and buys
  // nothing. Compared as bytes rather than through a string key, so no second copy of the key
  // material outlives this function.
  const unique: Uint8Array[] = [];
  for (const secret of list) {
    const bytes = parseStandardWebhooksSecret(secret, { usage });
    if (unique.some((seen) => bytesEqual(seen, bytes))) {
      continue;
    }
    unique.push(bytes);
    if (unique.length > MAX_SECRETS) {
      throw new Error(`secrets must not contain more than ${MAX_SECRETS} distinct entries`);
    }
  }

  return unique as [Uint8Array, ...Uint8Array[]];
}

function assertSignableMessageId(messageId: string): void {
  if (typeof messageId !== 'string' || messageId.length === 0) {
    throw new TypeError('messageId must be a non-empty string');
  }
  if (UNSIGNABLE_MESSAGE_ID.test(messageId)) {
    throw new TypeError(
      "messageId must not contain '.' or whitespace: the dot is the field delimiter in the signed " +
        'value and the signature header is a space-separated list, so an id holding either makes ' +
        'the message re-splittable. Ids that do are still accepted on the verify path, because ' +
        'they are legal in the specification and refusing them would only break interoperability',
    );
  }
  assertWellFormed(messageId, 'messageId');
}

function assertSignablePayload(payload: WebhookPayload): void {
  if (typeof payload === 'string') {
    assertWellFormed(payload, 'payload');
    return;
  }
  if (!(payload instanceof Uint8Array)) {
    throw new TypeError('payload must be a string or a Uint8Array');
  }

  // The reference implementations do not agree on a body that is not well-formed UTF-8: Go signs
  // the bytes, Rust refuses the message, and JavaScript and Python decode to a string first and
  // sign a mangled copy. There is no digest that satisfies all of them, so rather than pick one
  // and produce a signature some receivers compute differently, the emitter refuses. A loud
  // failure at send time beats a silent mismatch at the far end. The verify path has no such
  // problem and takes the bytes as they come.
  try {
    FATAL_UTF8.decode(payload);
  } catch {
    throw new TypeError(
      'payload is not well-formed UTF-8. Standard Webhooks receivers do not agree on what such a ' +
        'body signs to - Go signs the bytes, Rust refuses them, JavaScript and Python sign a ' +
        'mangled copy - so no signature emitted here would be correct for all of them',
    );
  }
}

/**
 * `String.prototype.isWellFormed`, reached through a cast.
 *
 * The method is ES2024 and this package compiles under `lib: ["ES2022"]`, so TypeScript does not
 * know about it; widening `lib` to reach one method would also let every later global into `src`
 * unnoticed. There is no fallback branch: it is present on every runtime this package supports
 * (Node 20+, and the engines floor here is 22), and a fallback would be a second implementation of
 * the check that no CI job ever executes.
 */
type WellFormed = { isWellFormed(): boolean };

const UNPAIRED_SURROGATE =
  'contains an unpaired surrogate. UTF-8 encoding maps every one of them onto the same three ' +
  'replacement bytes, so two different strings would sign to one digest';

function assertWellFormed(text: string, field: string): void {
  if (!(text as unknown as WellFormed).isWellFormed()) {
    throw new TypeError(`${field} ${UNPAIRED_SURROGATE}`);
  }
}

function readHeaders(source: Record<string, string | string[] | undefined>): {
  id: string;
  timestamp: string;
  signature: string;
} {
  if (typeof source !== 'object' || source === null) {
    throw new WebhookSignatureError('Webhook headers are missing');
  }

  // Header names are case-insensitive on the wire and the reference libraries disagree about
  // handling that - two of them lower-case, one scans case-insensitively, two relied on their HTTP
  // framework and had to be fixed. Lower-casing here means a caller can hand over whatever its
  // framework produced. Two spellings of one name are refused rather than resolved by insertion
  // order, which would let a proxy decide which value gets verified.
  const found = new Map<string, string | string[] | undefined>();
  for (const [name, value] of Object.entries(source)) {
    const key = name.toLowerCase();
    if (!HEADER_NAMES.includes(key)) {
      continue;
    }
    if (found.has(key)) {
      throw new WebhookSignatureError(`Webhook header is duplicated: ${key}`);
    }
    found.set(key, value);
  }

  return {
    id: readHeader(found, ID_HEADER),
    timestamp: readHeader(found, TIMESTAMP_HEADER),
    signature: readHeader(found, SIGNATURE_HEADER),
  };
}

/**
 * One header value, or a failure.
 *
 * An array means some layer kept duplicate headers apart instead of folding them, and taking the
 * first entry would drop the rest without saying so. An empty string is treated as absent: a
 * framework that reports a missing header as '' would otherwise hand the verifier a value it
 * would then fail on for a less useful reason.
 */
function readHeader(headers: Map<string, string | string[] | undefined>, name: string): string {
  const raw = headers.get(name);
  if (Array.isArray(raw) && raw.length > 1) {
    throw new WebhookSignatureError(`Webhook header is duplicated: ${name}`);
  }

  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || value === '') {
    throw new WebhookSignatureError(`Webhook header is missing: ${name}`);
  }
  return value;
}

/**
 * The usable `v1` digests in a `webhook-signature` value.
 *
 * Unknown tags and malformed entries are skipped rather than refused, which inverts what
 * `verifyWebhook` does with this package's own header, where an unrecognised version is rejected
 * outright. Two headers, two rules, and the reason is that they are two different contracts.
 *
 * Skipping is what the specification's rotation model needs - a sender emits several entries and a
 * receiver is expected to ignore the ones it cannot read - and it is what four of the five
 * reference libraries do. Their own multi-signature tests put a `v2,` entry beside a valid one and
 * require the request to succeed, so this behaviour is externally specified rather than chosen.
 * The fifth, Python, has no guard and raises on `garbage v1,<valid>`, which turns an
 * attacker-chosen header into a 500 where a 401 belongs.
 *
 * Our own header stays strict for the opposite reason: it has one version, we control both ends of
 * it, and quietly ignoring a signature we do not understand there would hide a downgrade.
 */
function parseDigests(header: string): Uint8Array[] {
  const digests: Uint8Array[] = [];

  for (const entry of header.split(' ')) {
    const comma = entry.indexOf(',');
    if (comma === -1 || entry.slice(0, comma) !== SIGNATURE_TAG) {
      continue;
    }

    let digest: Uint8Array;
    try {
      digest = fromBase64(entry.slice(comma + 1));
    } catch {
      continue;
    }
    if (digest.length !== SHA256_DIGEST_BYTES) {
      continue;
    }
    digests.push(digest);
  }

  return digests;
}
