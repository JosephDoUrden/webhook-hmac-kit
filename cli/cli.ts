/**
 * `webhook-hmac-kit vectors`: prints the test-vector corpus, or runs a corpus file through this
 * library and says which cases pass.
 *
 * Node only, so it lives outside src/, which must stay free of `node:` imports. It is a separate
 * build entry, and the build rewrites its `../src/index.js` import to a runtime `./index.js`, so
 * the binary checks the same dist/index.js a caller gets rather than a private copy bundled into
 * itself. The corpus is inlined at build time, so the binary never has to find vectors/ on disk.
 *
 * Exit codes: 0 every case passed, 1 a case failed or the file could not be used, 2 usage.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import {
  WebhookError,
  signStandardWebhooks,
  signWebhook,
  verifyStandardWebhooks,
  verifyWebhook,
} from '../src/index.js';
import standardWebhooksCorpus from '../vectors/standard-webhooks.json';
import v2Corpus from '../vectors/v2.json';

/** Where the CLI writes and reads. Injected so the commands can be tested without a process. */
export interface CliIO {
  stdout(text: string): void;
  stderr(text: string): void;
  readFile(path: string): string;
}

/** The outcome of one corpus case. `reason` is set only when it failed. */
export interface CaseResult {
  scheme: string;
  name: string;
  passed: boolean;
  reason?: string | undefined;
}

const USAGE = `Usage: webhook-hmac-kit vectors [--scheme sw|v2]
       webhook-hmac-kit vectors --verify <file.json>

  vectors                  Print the test-vector corpus as JSON (both schemes unless --scheme).
  vectors --verify <file>  Run every case in a corpus file through this library. Exits 1 if any
                           case fails.
`;

const SCHEMES = {
  sw: standardWebhooksCorpus,
  v2: v2Corpus,
} as const;

const SW_SCHEME = 'standard-webhooks';
const V2_SCHEME = 'webhook-hmac-kit-v2';

/** Standard alphabet, padded, and nothing else. */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const nodeIO: CliIO = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  readFile: (path) => readFileSync(path, 'utf8'),
};

/** Runs one command line (without the `node` and script entries) and resolves to its exit code. */
export async function runCli(argv: string[], io: CliIO = nodeIO): Promise<number> {
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(argv);
  } catch (error) {
    io.stderr(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }

  if (parsed.values.help) {
    io.stdout(USAGE);
    return 0;
  }

  const [command, ...rest] = parsed.positionals;
  if (command !== 'vectors' || rest.length > 0) {
    io.stderr(USAGE);
    return 2;
  }

  const { scheme, verify } = parsed.values;
  if (verify !== undefined) {
    if (scheme !== undefined) {
      io.stderr(`--scheme cannot be combined with --verify\n\n${USAGE}`);
      return 2;
    }
    return verifyFile(verify, io);
  }

  if (scheme === undefined) {
    io.stdout(`${JSON.stringify([SCHEMES.sw, SCHEMES.v2], null, 2)}\n`);
    return 0;
  }
  if (scheme !== 'sw' && scheme !== 'v2') {
    io.stderr(`--scheme must be one of: sw, v2\n\n${USAGE}`);
    return 2;
  }
  io.stdout(`${JSON.stringify(SCHEMES[scheme], null, 2)}\n`);
  return 0;
}

function parse(argv: string[]) {
  return parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      scheme: { type: 'string' },
      verify: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
}

async function verifyFile(path: string, io: CliIO): Promise<number> {
  let text: string;
  try {
    text = io.readFile(path);
  } catch (error) {
    io.stderr(`cannot read ${path}: ${(error as Error).message}\n`);
    return 1;
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    io.stderr(`${path} is not valid JSON\n`);
    return 1;
  }

  let results: CaseResult[];
  try {
    results = await verifyCorpora(data);
  } catch (error) {
    io.stderr(`${path}: ${(error as Error).message}\n`);
    return 1;
  }

  let failed = 0;
  for (const result of results) {
    if (result.passed) {
      io.stdout(`ok   ${result.scheme}: ${result.name}\n`);
    } else {
      failed += 1;
      io.stdout(`FAIL ${result.scheme}: ${result.name}\n     ${result.reason}\n`);
    }
  }
  io.stdout(`\n${results.length - failed} passed, ${failed} failed\n`);
  return failed === 0 ? 0 : 1;
}

/**
 * Runs a parsed corpus file: one corpus, or an array of them as `vectors` prints. Throws only when
 * the file as a whole is unusable; a bad case is a failed result, not an exception.
 */
export async function verifyCorpora(data: unknown): Promise<CaseResult[]> {
  const corpora = Array.isArray(data) ? data : [data];
  if (corpora.length === 0) {
    throw new Error('no corpus in the file');
  }

  const results: CaseResult[] = [];
  for (const corpus of corpora) {
    const fields = asObject<'scheme' | 'tolerance' | 'cases'>(corpus);
    const cases = fields?.cases;
    if (!fields || !Array.isArray(cases)) {
      throw new Error('a corpus must be an object with a cases array');
    }
    const scheme = fields.scheme;
    if (scheme !== SW_SCHEME && scheme !== V2_SCHEME) {
      throw new Error(`unknown scheme ${JSON.stringify(scheme)}`);
    }
    if (cases.length === 0) {
      throw new Error(`the ${scheme} corpus has no cases`);
    }
    const tolerance = fields.tolerance;
    if (tolerance !== undefined && typeof tolerance !== 'number') {
      throw new Error('tolerance must be a number');
    }

    for (const [index, raw] of cases.entries()) {
      const label = asObject<'name'>(raw)?.name;
      const name = typeof label === 'string' ? label : `case ${index}`;
      try {
        await runCase(scheme, raw, tolerance);
        results.push({ scheme, name, passed: true });
      } catch (error) {
        results.push({ scheme, name, passed: false, reason: (error as Error).message });
      }
    }
  }
  return results;
}

type Expectation =
  | { kind: 'valid' }
  | { kind: 'error'; code: string }
  | { kind: 'reject'; stage: 'sign' | 'verify' };

type Direction = 'sign+verify' | 'verify-only' | 'sign-only';

const PAIRING =
  "a valid case is 'sign+verify' or 'verify-only', an error case is 'verify-only', and a " +
  "case refused at sign is 'sign-only'";

/** The directions each expectation can be paired with. Anything else contradicts itself. */
function allowedDirections(expectation: Expectation): Direction[] {
  if (expectation.kind === 'valid') {
    return ['sign+verify', 'verify-only'];
  }
  return [
    expectation.kind === 'reject' && expectation.stage === 'sign' ? 'sign-only' : 'verify-only',
  ];
}

/** Resolves when the case holds, throws an Error saying why when it does not. */
async function runCase(
  scheme: typeof SW_SCHEME | typeof V2_SCHEME,
  raw: unknown,
  tolerance: number | undefined,
): Promise<void> {
  const fields = asObject<CaseField>(raw);
  if (!fields) {
    throw new Error('case is not an object');
  }
  const secrets = readSecrets(fields);
  const timestamp = readNumber(fields, 'timestamp');
  const now = readNumber(fields, 'now');
  const payload = readPayload(fields.payload);
  const direction = fields.direction;
  if (direction !== 'sign+verify' && direction !== 'verify-only' && direction !== 'sign-only') {
    throw new Error("direction must be 'sign+verify', 'verify-only' or 'sign-only'");
  }
  if (fields.conformance !== 'spec' && fields.conformance !== 'webhook-hmac-kit') {
    throw new Error("conformance must be 'spec' or 'webhook-hmac-kit'");
  }
  const expectation = readExpect(fields.expect);
  if (!allowedDirections(expectation).includes(direction)) {
    throw new Error(
      `direction ${direction} contradicts expect ${JSON.stringify(fields.expect)}: ${PAIRING}`,
    );
  }

  /** Signs and resolves to the signature value, or throws whatever the signer threw. */
  let signRaw: () => Promise<string>;
  let expectedSignature: string | undefined;
  let verify: () => Promise<unknown>;

  if (scheme === SW_SCHEME) {
    const messageId = readString(fields, 'messageId');
    const headers = asObject<string>(fields.headers);
    if (!headers || !Object.values(headers).every((v) => typeof v === 'string')) {
      throw new Error('headers must be an object of strings');
    }
    expectedSignature = (headers as Record<string, string>)['webhook-signature'];
    signRaw = async () =>
      (await signStandardWebhooks({ secrets, messageId, timestamp, payload }))['webhook-signature'];
    verify = () =>
      verifyStandardWebhooks({
        secrets,
        headers: headers as Record<string, string>,
        payload,
        tolerance,
        now,
      });
  } else {
    const nonce = readString(fields, 'nonce');
    const signature = readString(fields, 'signature');
    expectedSignature = signature;
    signRaw = async () => (await signWebhook({ secrets, payload, timestamp, nonce })).signature;
    verify = () => verifyWebhook({ secrets, payload, signature, timestamp, nonce, tolerance, now });
  }

  if (expectation.kind === 'reject') {
    // Both signers throw synchronously by design; wrapped in a promise it is the same observation.
    const refused = await (expectation.stage === 'sign' ? signRaw() : verify()).then(
      () => false,
      () => true,
    );
    if (!refused) {
      throw new Error(
        `expected the ${expectation.stage === 'sign' ? 'signer' : 'verifier'} to refuse`,
      );
    }
    return;
  }

  if (expectation.kind === 'error') {
    const outcome = await verify().then(
      () => undefined,
      (error: unknown) => error,
    );
    if (!(outcome instanceof WebhookError) || outcome.code !== expectation.code) {
      throw new Error(`expected ${expectation.code}, got ${describe(outcome)}`);
    }
    return;
  }

  if (direction === 'sign+verify') {
    const signed = await signRaw();
    if (signed !== expectedSignature) {
      throw new Error(`signed to ${signed}, expected ${expectedSignature}`);
    }
  }
  const outcome = await verify().then(
    () => undefined,
    (error: unknown) => error,
  );
  if (outcome !== undefined) {
    throw new Error(`expected valid, got ${describe(outcome)}`);
  }
}

function describe(outcome: unknown): string {
  if (outcome === undefined) {
    return 'success';
  }
  if (outcome instanceof WebhookError) {
    return outcome.code;
  }
  return outcome instanceof Error ? `${outcome.name}: ${outcome.message}` : String(outcome);
}

/** A parsed JSON object whose fields have not been checked yet. */
type Unchecked<K extends string> = { readonly [P in K]?: unknown };

type CaseField =
  | 'name'
  | 'secret'
  | 'secrets'
  | 'messageId'
  | 'nonce'
  | 'timestamp'
  | 'now'
  | 'payload'
  | 'headers'
  | 'signature'
  | 'direction'
  | 'conformance'
  | 'expect';

function asObject<K extends string>(value: unknown): Unchecked<K> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Unchecked<K>)
    : undefined;
}

function readString(raw: Unchecked<CaseField>, key: 'messageId' | 'nonce' | 'signature'): string {
  const value = raw[key];
  if (typeof value !== 'string') {
    throw new Error(`${key} must be a string`);
  }
  return value;
}

function readNumber(raw: Unchecked<CaseField>, key: 'timestamp' | 'now'): number {
  const value = raw[key];
  if (typeof value !== 'number') {
    throw new Error(`${key} must be a number`);
  }
  return value;
}

function readSecrets(raw: Unchecked<CaseField>): string[] {
  const list = raw.secrets ?? (raw.secret === undefined ? undefined : [raw.secret]);
  if (!Array.isArray(list) || list.length === 0 || !list.every((s) => typeof s === 'string')) {
    throw new Error('secret must be a string, or secrets a non-empty array of strings');
  }
  return list;
}

function readPayload(value: unknown): Uint8Array {
  const fields = asObject<'base64' | 'utf8'>(value);
  const encoded = fields?.base64;
  if (typeof encoded !== 'string' || !BASE64.test(encoded)) {
    throw new Error('payload.base64 must be padded standard-alphabet base64');
  }
  const bytes = new Uint8Array(Buffer.from(encoded, 'base64'));
  const text = fields?.utf8;
  if (text !== undefined) {
    if (typeof text !== 'string' || Buffer.compare(Buffer.from(text, 'utf8'), bytes) !== 0) {
      throw new Error('payload.utf8 does not match payload.base64');
    }
  }
  return bytes;
}

function readExpect(value: unknown): Expectation {
  if (value === 'valid') {
    return { kind: 'valid' };
  }
  const fields = asObject<'error' | 'reject'>(value);
  if (typeof fields?.error === 'string') {
    return { kind: 'error', code: fields.error };
  }
  const stage = fields?.reject;
  if (stage === 'sign' || stage === 'verify') {
    return { kind: 'reject', stage };
  }
  throw new Error("expect must be 'valid', { error: <code> }, or { reject: 'sign' | 'verify' }");
}

/** True when this file is the process entry point, including through npm's bin symlink. */
function isMain(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) {
    return false;
  }
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  process.exitCode = await runCli(process.argv.slice(2));
}
