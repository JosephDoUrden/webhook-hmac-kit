/**
 * The HMAC-SHA256 layer, on Web Crypto and nothing else.
 *
 * One code path for every runtime. There is no node:crypto import, guarded or otherwise: a literal
 * 'node:crypto' specifier is resolved at bundle time by esbuild, wrangler, Vite and Metro whether
 * or not the surrounding code can run, so a try/catch around a dynamic import buys nothing and
 * costs every bundled build. Auth.js took the same position when it made the same move.
 */

const HMAC_SHA256 = { name: 'HMAC', hash: 'SHA-256' } as const;

/**
 * Web Crypto's types, derived from the global rather than named.
 *
 * SubtleCrypto, CryptoKey and BufferSource are not globals under `lib: ["ES2022"]`; they resolve
 * only through @types/node, and only from the 25 line — on 22, which is this package's engines
 * floor, all three are undeclared. Adding "DOM" to `lib` would supply them and also let every
 * browser-only API into src unnoticed, which is the larger problem. Reading the types off the
 * object we actually call works on every @types/node in range and cannot drift from it.
 */
type Subtle = NonNullable<typeof globalThis.crypto>['subtle'];
type HmacKey = Awaited<ReturnType<Subtle['importKey']>>;
type BytesForSubtle = Parameters<Subtle['digest']>[1];

/**
 * Widens a Uint8Array to the BufferSource the Web Crypto signatures ask for.
 *
 * TypeScript models BufferSource as excluding SharedArrayBuffer-backed views, so a plain
 * Uint8Array — whose buffer is ArrayBufferLike — does not satisfy it, and every call below would
 * need its own cast. The algorithms take "a copy of the bytes held by the buffer source" and have
 * no such restriction, and everything this module is handed came out of bytes.ts freshly
 * allocated. One cast, in one place, with the reason next to it.
 */
function bufferSource(bytes: Uint8Array): BytesForSubtle {
  return bytes as BytesForSubtle;
}

/** Thrown when the runtime has no Web Crypto to use. Carries the fix, because there is no fallback. */
export class WebCryptoUnavailableError extends Error {
  constructor() {
    super(
      'Web Crypto is unavailable: globalThis.crypto.subtle is missing, and this library ' +
        'has no fallback. ' +
        'On Node 22+ it is present by default unless the process was started with ' +
        '--no-experimental-global-webcrypto; remove that flag, or install the global before ' +
        "importing this library with: globalThis.crypto ??= require('node:crypto').webcrypto",
    );
    this.name = 'WebCryptoUnavailableError';
  }
}

/**
 * The ambient SubtleCrypto, or a useful error.
 *
 * Read fresh every time and never captured at module scope: on Workers the module body runs outside
 * a request, and a value cached there outlives the isolate that produced it.
 */
export function getSubtle(): Subtle {
  const subtle = globalThis.crypto?.subtle;
  if (typeof subtle !== 'object' || subtle === null) {
    throw new WebCryptoUnavailableError();
  }
  return subtle;
}

/**
 * Imports key material for HMAC-SHA256.
 *
 * Both usages, always. A key imported with ['sign'] alone makes subtle.verify throw on every
 * runtime, which turns a receiver into a 500 for reasons nobody can read off the stack.
 *
 * Non-extractable, and no key is memoised: importKey per call is what jose and octokit's web build
 * both do, and caching a CryptoKey across requests is the sort of cross-request state a Workers
 * isolate is entitled to refuse.
 */
export function importHmacKey(keyBytes: Uint8Array): Promise<HmacKey> {
  return getSubtle().importKey('raw', bufferSource(keyBytes), HMAC_SHA256, false, [
    'sign',
    'verify',
  ]);
}

/** The MAC of `data` under `keyBytes`, as 32 bytes. */
export async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const subtle = getSubtle();
  const key = await importHmacKey(keyBytes);
  return new Uint8Array(await subtle.sign(HMAC_SHA256.name, key, bufferSource(data)));
}

/**
 * Compares two MACs without letting the comparison itself say how far it got.
 *
 * The Web Crypto editor's draft has required constant-time HMAC verification since w3c/webcrypto
 * PR #553 (26 Mar 2026) — the editor's draft only; neither the 2017 Recommendation nor the Level 2
 * First Public Working Draft says it, and there is no web-platform-test for it, which is how Node
 * shipped a plain memcmp in crypto_hmac.cc for years (CVE-2026-21713, fixed 24 Mar 2026 in
 * v20.20.2, v22.22.2, v24.14.1 and v25.8.2). We do not control which patch level a consumer runs
 * on, so the compare has to stay sound on a runtime that has not been patched.
 *
 * Hence the Double-HMAC blind, in the form jose uses: draw a random 32-byte key, MAC both operands
 * under it, and compare the results. A leaky comparison then reveals only how two random-looking
 * digests agree, under a key that is discarded when this function returns — there is nothing an
 * attacker can iterate towards.
 *
 * Scope, stated honestly. Every other runtime we target was read at source and is already constant
 * time: workerd and Chromium use CRYPTO_memcmp, Firefox NSS_SecureMemcmp, WebKit's openssl and
 * gcrypt ports constantTimeMemcmp, Deno aws-lc / RustCrypto, and Node itself after b36d5a3d. The
 * only family this defends against is unpatched Node, and it is defence in depth — no remote
 * exploit of the underlying bug appears in any of the sources. The dissent is worth keeping: Miller
 * argues the threat models differ enough that this is not needed, and armfazh calls the blind an
 * abuse of the API. Both are reasonable; the deciding factor is that we ship a library and do not
 * choose our users' patch level.
 *
 * The fold below is JS and therefore not itself guaranteed constant time — hand-written JS cannot
 * be (CT-Wasm, POPL 2019; Pornin, IACR ePrint 2025/435), and nodejs/node#38226 measured t up to
 * 37.9 on the *native* primitive when unrelated JS changed. That is precisely why what it compares
 * is blinded rather than secret: the fold is allowed to leak.
 *
 * The blinding key comes from getRandomValues plus importKey rather than generateKey. generateKey
 * for HMAC needs an IoContext on Workers and throws outside a request, getRandomValues is the only
 * synchronous member of the Crypto interface and is present everywhere, and this way the key length
 * is ours to state.
 *
 * The known-bad list, so none of it comes back:
 *   - a bare JS byte loop as the primary compare. Deno's own is documented as "best-effort", and
 *     Node deleted its benchmark for the property after three years because it could not be
 *     measured.
 *   - '===' on the hex strings. That is hono, GHSA-gq3j-xvxp-8hrf.
 *   - a preference branch for Cloudflare's non-standard crypto.subtle.timingSafeEqual. It would be
 *     a second code path that no CI job here executes and live code on the runtime the migration
 *     exists for, and it throws on a length mismatch where this does not, leaking what verify hides.
 *   - per-runtime conditional exports, which jose abandoned because runtimes ignore their own
 *     conditions and reach for the Node build anyway.
 *   - a vendored hash. standardwebhooks still carries fast-sha256, three years stale.
 */
export async function blindedEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  const subtle = getSubtle();
  const blindingKey = await subtle.importKey(
    'raw',
    bufferSource(globalThis.crypto.getRandomValues(new Uint8Array(32))),
    HMAC_SHA256,
    false,
    ['sign'],
  );

  const [blindedA, blindedB] = await Promise.all([
    subtle.sign(HMAC_SHA256.name, blindingKey, bufferSource(a)),
    subtle.sign(HMAC_SHA256.name, blindingKey, bufferSource(b)),
  ]);

  const left = new Uint8Array(blindedA);
  const right = new Uint8Array(blindedB);

  // The length term is not what defends against a length mismatch — the blinding already does
  // that. Both digests are 32 bytes whatever went in, so operands of different lengths arrive here
  // as two different 32-byte values and fail on content, with no early return and nothing said
  // about which was longer. This term is insurance against a future change of digest size making
  // the two runs unequal, so that a shorter one could never compare equal to a prefix of a longer.
  // It is a constant under SHA-256 and costs nothing.
  let difference = left.length ^ right.length;
  for (let i = 0; i < left.length; i++) {
    difference |= (left[i] as number) ^ (right[i] as number);
  }
  return difference === 0;
}
