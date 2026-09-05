/**
 * A forgotten `await` on `fc.assert(fc.asyncProperty(...))` does not fail. The test finishes, is
 * reported as passed, and has verified nothing; vitest 2 only surfaces the problem as an unhandled
 * rejection, and only when the property would have failed anyway. So a green suite would be telling
 * us the encoding is injective when nobody had checked.
 *
 * Biome 1.9.4 has no noFloatingPromises - the rule arrived in 2.x as a type-aware nursery rule, and
 * `biome explain noFloatingPromises` on the installed binary says "Unrecognized option". tsc has no
 * equivalent, and @typescript-eslint/no-floating-promises would mean adding ESLint plus type-aware
 * linting to a Biome-only repo for one rule. This is the small version instead: read the sources,
 * find every fc.assert, and require the asynchronous ones to be awaited.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const TEST_DIR = new URL('.', import.meta.url).pathname;

/** This file quotes the pattern it is looking for, so it cannot be one of its own inputs. */
const SELF = 'await-guard.test.ts';

function testFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return testFiles(path);
    return path.endsWith('.test.ts') && entry.name !== SELF ? [path] : [];
  });
}

/** `fc.assert(` sites whose property is asynchronous and which are not awaited. */
function unawaitedAsyncAssertions(source: string, label: string): string[] {
  const offenders: string[] = [];
  const marker = 'fc.assert(';

  for (let at = source.indexOf(marker); at !== -1; at = source.indexOf(marker, at + 1)) {
    const isAsync = source.slice(at, at + 200).includes('fc.asyncProperty(');
    const isAwaited = source.slice(Math.max(0, at - 6), at) === 'await ';
    if (isAsync && !isAwaited) {
      offenders.push(`${label}:${source.slice(0, at).split('\n').length}`);
    }
  }
  return offenders;
}

const ASYNC_ASSERTION = ['fc.assert(', '  fc.asyncProperty(arb, async () => {}),', ');'].join('\n');
const SYNC_ASSERTION = ['fc.assert(', '  fc.property(arb, () => {}),', ');'].join('\n');

describe('async property assertions are awaited', () => {
  it('finds no unawaited fc.assert over an async property', () => {
    const offenders = testFiles(TEST_DIR).flatMap((file) =>
      unawaitedAsyncAssertions(readFileSync(file, 'utf8'), file.slice(TEST_DIR.length)),
    );

    expect(offenders).toEqual([]);
  });

  // A guard is worth exactly what it can see, so it is shown the mistake and its correction.
  it('sees the mistake when it is there', () => {
    expect(unawaitedAsyncAssertions(ASYNC_ASSERTION, 'sample.ts')).toEqual(['sample.ts:1']);
    expect(unawaitedAsyncAssertions(`await ${ASYNC_ASSERTION}`, 'sample.ts')).toEqual([]);
  });

  it('does not object to a synchronous property left unawaited', () => {
    expect(unawaitedAsyncAssertions(SYNC_ASSERTION, 'sample.ts')).toEqual([]);
  });
});
