import { readFileSync } from 'node:fs';
import { afterAll, describe, expect, it } from 'vitest';
import { fromBase64 } from '../src/bytes.js';
import {
  WebhookError,
  signStandardWebhooks,
  signWebhook,
  verifyStandardWebhooks,
  verifyWebhook,
} from '../src/index.js';

/**
 * Runs the published corpus in vectors/ through the public API.
 *
 * The corpus is written by scripts/gen-vectors.mjs with node:crypto alone, so a failure here means
 * the library and an independent HMAC disagree about a case, not that a fixture drifted with the
 * code. Every case carries the clock it expects (`now`), so nothing here touches the system time.
 */

type Expect = 'valid' | { error: string } | { reject: 'sign' | 'verify' };

interface BaseCase {
  name: string;
  conformance: 'spec' | 'webhook-hmac-kit';
  secret?: string;
  secrets?: string[];
  timestamp: number;
  payload: { base64: string; utf8?: string };
  direction: 'sign+verify' | 'verify-only' | 'sign-only';
  now: number;
  expect: Expect;
  source: string;
}

interface StandardWebhooksCase extends BaseCase {
  messageId: string;
  headers: Record<string, string>;
}

interface V2Case extends BaseCase {
  nonce: string;
  signature: string;
}

interface Corpus<C> {
  scheme: string;
  version: number;
  note: string;
  tolerance: number;
  cases: C[];
}

/** Pinned rather than counted, so a case that silently drops out of the generator is noticed. */
const SW_CASES = 17;
const V2_CASES = 16;
const NOTE = 'Public test keys. Never use outside tests.';

function load<C>(file: string): Corpus<C> {
  return JSON.parse(readFileSync(new URL(`../vectors/${file}`, import.meta.url), 'utf8'));
}

function secretsOf(c: BaseCase): string[] {
  const list = c.secrets ?? (c.secret === undefined ? [] : [c.secret]);
  expect(list.length, `${c.name}: no secret`).toBeGreaterThan(0);
  return list;
}

function payloadOf(c: BaseCase): Uint8Array {
  const bytes = fromBase64(c.payload.base64);
  if (c.payload.utf8 !== undefined) {
    // The utf8 field is documentation; it must never say something the bytes do not.
    expect(new TextEncoder().encode(c.payload.utf8)).toEqual(bytes);
  }
  return bytes;
}

/** The fields every case must carry, and the direction its expectation allows. */
function checkShape(c: BaseCase): void {
  expect(['spec', 'webhook-hmac-kit']).toContain(c.conformance);
  expect(Number.isSafeInteger(c.now), `${c.name}: now is required`).toBe(true);
  expect(typeof c.source).toBe('string');
  if (c.expect === 'valid') {
    expect(['sign+verify', 'verify-only']).toContain(c.direction);
  } else if ('error' in c.expect) {
    expect(c.direction).toBe('verify-only');
  } else {
    expect(c.direction).toBe(c.expect.reject === 'sign' ? 'sign-only' : 'verify-only');
  }
}

async function expectError(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(WebhookError);
  expect((error as WebhookError).code).toBe(code);
}

const sw = load<StandardWebhooksCase>('standard-webhooks.json');
const v2 = load<V2Case>('v2.json');
const ran = new Set<string>();

afterAll(() => {
  // A case that no branch below handled would otherwise pass by being skipped.
  expect(ran.size).toBe(SW_CASES + V2_CASES);
});

describe('vectors/standard-webhooks.json', () => {
  it('is the Standard Webhooks corpus', () => {
    expect(sw.scheme).toBe('standard-webhooks');
    expect(sw.version).toBe(1);
    expect(sw.note).toBe(NOTE);
    expect(sw.cases).toHaveLength(SW_CASES);
    expect(new Set(sw.cases.map((c) => c.name)).size).toBe(SW_CASES);
  });

  // Only this library's own choices are marked as such; everything else is what any conforming
  // implementation has to agree with.
  it('marks the cap and the sign-time key range as this library policy', () => {
    const own = sw.cases.filter((c) => c.conformance === 'webhook-hmac-kit').map((c) => c.name);
    expect(own).toEqual([
      'a valid entry seventeenth in the list is past the cap and not found',
      'a 23-byte key is refused at sign time',
    ]);
  });

  it.each(sw.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    checkShape(c);
    const secrets = secretsOf(c);
    const payload = payloadOf(c);
    const sign = () =>
      signStandardWebhooks({ secrets, messageId: c.messageId, timestamp: c.timestamp, payload });
    const verify = () =>
      verifyStandardWebhooks({
        secrets,
        headers: c.headers,
        payload,
        tolerance: sw.tolerance,
        now: c.now,
      });

    if (c.expect === 'valid') {
      if (c.direction === 'sign+verify') {
        expect(await sign()).toEqual(c.headers);
      }
      await expect(verify()).resolves.toEqual({ valid: true });
    } else if ('error' in c.expect) {
      await expectError(verify(), c.expect.error);
    } else if (c.expect.reject === 'sign') {
      // Synchronously: the signers are deliberately not async, so a bad argument throws.
      expect(sign).toThrow(TypeError);
    } else {
      await expect(verify()).rejects.toThrow(TypeError);
    }
    ran.add(`sw:${c.name}`);
  });
});

describe('vectors/v2.json', () => {
  it('is the v2 corpus', () => {
    expect(v2.scheme).toBe('webhook-hmac-kit-v2');
    expect(v2.version).toBe(1);
    expect(v2.note).toBe(NOTE);
    expect(v2.cases).toHaveLength(V2_CASES);
    expect(new Set(v2.cases.map((c) => c.name)).size).toBe(V2_CASES);
  });

  it('marks every case as this library policy, since the scheme is its own', () => {
    expect(v2.cases.every((c) => c.conformance === 'webhook-hmac-kit')).toBe(true);
  });

  it.each(v2.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    checkShape(c);
    const secrets = secretsOf(c);
    const payload = payloadOf(c);
    const sign = () => signWebhook({ secrets, payload, timestamp: c.timestamp, nonce: c.nonce });
    const verify = () =>
      verifyWebhook({
        secrets,
        payload,
        signature: c.signature,
        timestamp: c.timestamp,
        nonce: c.nonce,
        tolerance: v2.tolerance,
        now: c.now,
      });

    if (c.expect === 'valid') {
      if (c.direction === 'sign+verify') {
        expect((await sign()).signature).toBe(c.signature);
      }
      await expect(verify()).resolves.toEqual({ valid: true });
    } else if ('error' in c.expect) {
      await expectError(verify(), c.expect.error);
    } else if (c.expect.reject === 'sign') {
      expect(sign).toThrow(TypeError);
    } else {
      await expect(verify()).rejects.toThrow(TypeError);
    }
    ran.add(`v2:${c.name}`);
  });
});
