import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { type CliIO, runCli } from '../cli/cli.js';

/**
 * The CLI's command functions, called in-process. Nothing here spawns dist/: CI runs the tests
 * before the build, and ci.yml runs the built binary over the corpus as its own step.
 */

const SW_PATH = 'vectors/standard-webhooks.json';
const V2_PATH = 'vectors/v2.json';
const swText = readFileSync(SW_PATH, 'utf8');
const v2Text = readFileSync(V2_PATH, 'utf8');

function fakeIO(files: Record<string, string> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIO = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    readFile: (path) => {
      const text = files[path];
      if (text === undefined) {
        throw Object.assign(new Error(`ENOENT: no such file or directory, open '${path}'`), {
          code: 'ENOENT',
        });
      }
      return text;
    },
  };
  return {
    io,
    stdout: () => out.join(''),
    stderr: () => err.join(''),
  };
}

type MutableCase = {
  expect?: unknown;
  direction?: unknown;
  secret?: unknown;
  [key: string]: unknown;
};

function isReject(value: unknown): boolean {
  return typeof value === 'object' && value !== null && 'reject' in value;
}

/** A copy of a corpus with one case changed, as a string ready to be "read". */
function mutate(text: string, change: (corpus: { cases: MutableCase[] }) => void) {
  const corpus = JSON.parse(text);
  change(corpus);
  return JSON.stringify(corpus);
}

describe('vectors', () => {
  it('prints both corpora, unchanged, when no scheme is named', async () => {
    const run = fakeIO();
    expect(await runCli(['vectors'], run.io)).toBe(0);
    expect(JSON.parse(run.stdout())).toEqual([JSON.parse(swText), JSON.parse(v2Text)]);
  });

  it.each([
    ['sw', swText],
    ['v2', v2Text],
  ])('prints one corpus with --scheme %s', async (scheme, text) => {
    const run = fakeIO();
    expect(await runCli(['vectors', '--scheme', scheme], run.io)).toBe(0);
    expect(JSON.parse(run.stdout())).toEqual(JSON.parse(text));
  });

  it('refuses a scheme it does not know', async () => {
    const run = fakeIO();
    expect(await runCli(['vectors', '--scheme', 'v1'], run.io)).toBe(2);
    expect(run.stderr()).toMatch(/--scheme must be one of: sw, v2/);
    expect(run.stdout()).toBe('');
  });

  it('refuses --scheme together with --verify', async () => {
    const run = fakeIO({ [SW_PATH]: swText });
    expect(await runCli(['vectors', '--verify', SW_PATH, '--scheme', 'sw'], run.io)).toBe(2);
  });
});

describe('vectors --verify', () => {
  it.each([
    [SW_PATH, swText],
    [V2_PATH, v2Text],
  ])('passes every case in %s', async (path, text) => {
    const run = fakeIO({ [path]: text });
    expect(await runCli(['vectors', '--verify', path], run.io)).toBe(0);
    const count = JSON.parse(text).cases.length;
    expect(run.stdout()).toContain(`${count} passed, 0 failed`);
    expect(run.stdout()).not.toContain('FAIL');
  });

  it('passes what `vectors` prints, so the two commands round-trip', async () => {
    const print = fakeIO();
    await runCli(['vectors'], print.io);

    const run = fakeIO({ 'all.json': print.stdout() });
    expect(await runCli(['vectors', '--verify', 'all.json'], run.io)).toBe(0);
  });

  it('fails a corpus whose signature was tampered with, and names the case', async () => {
    const corrupted = mutate(swText, (corpus) => {
      const first = corpus.cases[0] as { headers: Record<string, string> };
      first.headers['webhook-signature'] = 'v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    });
    const run = fakeIO({ 'bad.json': corrupted });

    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(/FAIL standard-webhooks: the six-language de-facto vector/);
    expect(run.stdout()).toMatch(/1 failed/);
  });

  it('fails a v2 case whose payload was changed under its signature', async () => {
    const corrupted = mutate(v2Text, (corpus) => {
      const first = corpus.cases[0] as { payload: { base64: string; utf8?: string } };
      first.payload = { base64: Buffer.from('{}').toString('base64') };
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
  });

  it('fails a negative case relabelled as valid', async () => {
    const corrupted = mutate(v2Text, (corpus) => {
      const negative = corpus.cases.find((c) => typeof c.expect === 'object');
      if (!negative) throw new Error('corpus has no negative case');
      negative.expect = 'valid';
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
  });

  it('fails a negative case that names the wrong error code', async () => {
    const corrupted = mutate(v2Text, (corpus) => {
      const negative = corpus.cases.find((c) => typeof c.expect === 'object');
      if (!negative) throw new Error('corpus has no negative case');
      negative.expect = { error: 'WEBHOOK_NONCE_REPLAYED' };
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
  });

  it.each([
    ['an error case marked sign+verify', (c: MutableCase) => typeof c.expect === 'object'],
    ['a valid case marked sign-only', (c: MutableCase) => c.expect === 'valid'],
  ])('fails %s as a contradiction', async (_name, pick) => {
    const corrupted = mutate(v2Text, (corpus) => {
      const target = corpus.cases.find(pick);
      if (!target) throw new Error('corpus has no such case');
      target.direction = target.expect === 'valid' ? 'sign-only' : 'sign+verify';
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(/contradicts/);
  });

  it('fails a reject-at-sign case marked sign+verify as a contradiction', async () => {
    const corrupted = mutate(swText, (corpus) => {
      const target = corpus.cases.find((c) => isReject(c.expect));
      if (!target) throw new Error('corpus has no reject case');
      target.direction = 'sign+verify';
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(/contradicts/);
  });

  it('fails a reject-at-sign case whose signer accepts', async () => {
    const corrupted = mutate(swText, (corpus) => {
      const target = corpus.cases.find((c) => isReject(c.expect));
      if (!target) throw new Error('corpus has no reject case');
      target.secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(/expected the signer to refuse/);
  });

  it.each([
    ['now', /now must be a number/],
    ['conformance', /conformance must be 'spec' or 'webhook-hmac-kit'/],
  ])('fails a case with no %s', async (field, message) => {
    const corrupted = mutate(swText, (corpus) => {
      const { [field]: _dropped, ...rest } = corpus.cases[0] as MutableCase;
      corpus.cases[0] = rest;
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(message);
  });

  it('reports a malformed case as a failure instead of crashing', async () => {
    const corrupted = mutate(swText, (corpus) => {
      corpus.cases[0] = { name: 'no payload here' };
    });
    const run = fakeIO({ 'bad.json': corrupted });

    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
    expect(run.stdout()).toMatch(/FAIL standard-webhooks: no payload here/);
    expect(run.stdout()).toMatch(/1 failed/);
  });

  it('refuses base64 that is not in canonical standard form', async () => {
    const corrupted = mutate(v2Text, (corpus) => {
      const first = corpus.cases[0] as { payload: { base64: string } };
      first.payload.base64 = `${first.payload.base64}\n`;
    });
    const run = fakeIO({ 'bad.json': corrupted });
    expect(await runCli(['vectors', '--verify', 'bad.json'], run.io)).toBe(1);
  });

  it('fails a corpus with no cases rather than passing it vacuously', async () => {
    const run = fakeIO({
      'empty.json': JSON.stringify({ scheme: 'standard-webhooks', cases: [] }),
    });
    expect(await runCli(['vectors', '--verify', 'empty.json'], run.io)).toBe(1);
    expect(run.stderr()).toMatch(/no cases/);
  });

  it('fails a corpus for a scheme it does not know', async () => {
    const run = fakeIO({ 'x.json': JSON.stringify({ scheme: 'not-a-scheme', cases: [{}] }) });
    expect(await runCli(['vectors', '--verify', 'x.json'], run.io)).toBe(1);
    expect(run.stderr()).toMatch(/unknown scheme/);
  });

  it('fails a file that is not JSON', async () => {
    const run = fakeIO({ 'x.json': '{ not json' });
    expect(await runCli(['vectors', '--verify', 'x.json'], run.io)).toBe(1);
    expect(run.stderr()).toMatch(/x\.json is not valid JSON/);
  });

  it('fails a file that cannot be read', async () => {
    const run = fakeIO();
    expect(await runCli(['vectors', '--verify', 'missing.json'], run.io)).toBe(1);
    expect(run.stderr()).toMatch(/cannot read missing\.json/);
  });
});

describe('the package exports', () => {
  // Self-reference by package name goes through `exports`, the same map a consumer's resolver
  // reads, so this fails if the corpus is not reachable as `webhook-hmac-kit/vectors/...`.
  it.each(['standard-webhooks.json', 'v2.json'])('resolve vectors/%s', (file) => {
    const require = createRequire(import.meta.url);
    const resolved = require.resolve(`webhook-hmac-kit/vectors/${file}`);
    expect(resolved).toBe(fileURLToPath(new URL(`../vectors/${file}`, import.meta.url)));
  });
});

describe('usage', () => {
  it.each([
    ['no command', []],
    ['an unknown command', ['sign']],
    ['an unknown option', ['vectors', '--frobnicate']],
    ['a stray argument', ['vectors', 'extra']],
    ['--verify with no file', ['vectors', '--verify']],
  ])('answers %s with usage on stderr and exit 2', async (_name, argv) => {
    const run = fakeIO();
    expect(await runCli(argv, run.io)).toBe(2);
    expect(run.stderr()).toMatch(/Usage: webhook-hmac-kit vectors/);
    expect(run.stdout()).toBe('');
  });

  it('prints usage on stdout for --help', async () => {
    const run = fakeIO();
    expect(await runCli(['--help'], run.io)).toBe(0);
    expect(run.stdout()).toMatch(/Usage: webhook-hmac-kit vectors/);
  });
});
