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
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// fileURLToPath, not .pathname: the raw pathname keeps percent-encoding, so a checkout under a
// directory with a space in it yields '%20' and readdirSync fails on a path that does not exist.
const TEST_DIR = fileURLToPath(new URL('.', import.meta.url));

/** This file quotes the pattern it is looking for, so it cannot be one of its own inputs. */
const SELF = 'await-guard.test.ts';

function testFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return testFiles(path);
    return path.endsWith('.test.ts') && entry.name !== SELF ? [path] : [];
  });
}

/**
 * Blanks out comments, keeping every offset and line break so positions still line up.
 *
 * Only block comments and comments that own their whole line, because a `//` anywhere else could
 * be inside a string - `https://example.com` appears in the vectors - and eating to end of line
 * there could swallow a real `await`. Both forms of prose that could sit between an assert and its
 * property are covered, which is what this needs.
 */
function withoutComments(source: string): string {
  const blank = (text: string) => text.replace(/[^\n]/g, ' ');
  return source.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/^[ \t]*\/\/[^\n]*/gm, blank);
}

/**
 * The text from the start of the enclosing statement up to `at`.
 *
 * Walks backwards keeping bracket depth, so it steps over whole balanced groups - the previous
 * argument to the same call, a preceding callback body - and keeps going outward through the `(`
 * and `[` that enclose us, which is how `await Promise.all([fc.assert(...)])` is reached from the
 * inner call. It stops at a `;` or at the `{` that opens the enclosing block, both at depth zero.
 */
function statementHead(source: string, at: number): string {
  let depth = 0;
  let i = at - 1;

  for (; i >= 0; i--) {
    const char = source[i];
    if (char === ')' || char === ']' || char === '}') {
      depth += 1;
    } else if (char === '(' || char === '[' || char === '{') {
      if (depth > 0) depth -= 1;
      else if (char === '{') break;
    } else if (char === ';' && depth === 0) {
      break;
    }
  }
  return source.slice(i + 1, at);
}

/**
 * Async property sites that nothing in their statement awaits.
 *
 * Scanning from the property rather than from `fc.assert(` is what makes a hoisted property
 * visible: `const p = fc.asyncProperty(...)` is its own statement, nothing awaits it, and it is
 * reported. That is stricter than strictly necessary - `const p = ...; await fc.assert(p)` is
 * correct and still flagged - and deliberately so, since resolving it would mean following
 * assignments, and writing the property inline costs nothing.
 *
 * Requiring `await` anywhere in the statement head rather than immediately before `fc.assert`
 * leaves room for the combinators: Promise.all over several properties is awaited once, on the
 * combinator.
 */
function unawaitedAsyncAssertions(rawSource: string, label: string): string[] {
  const source = withoutComments(rawSource);
  const offenders: string[] = [];
  const marker = 'fc.asyncProperty(';

  for (let at = source.indexOf(marker); at !== -1; at = source.indexOf(marker, at + 1)) {
    if (!/\bawait\b/.test(statementHead(source, at))) {
      offenders.push(`${label}:${source.slice(0, at).split('\n').length}`);
    }
  }
  return offenders;
}

const ASYNC_ASSERTION = ['fc.assert(', '  fc.asyncProperty(arb, async () => {}),', ');'].join('\n');
const SYNC_ASSERTION = ['fc.assert(', '  fc.property(arb, () => {}),', ');'].join('\n');

// The four shapes the review asked about. Two must be caught and two must be left alone; a guard
// that gets any of them wrong is either lying about coverage or training people to ignore it.
const HOISTED_UNAWAITED = [
  'const property = fc.asyncProperty(arb, async () => {});',
  'fc.assert(property);',
].join('\n');

const LONG_COMMENT_BEFORE = [
  'fc.assert(',
  `  // ${'a lengthy justification for this property. '.repeat(8)}`,
  '  fc.asyncProperty(arb, async () => {}),',
  ');',
].join('\n');

const SYNC_THEN_AWAITED_ASYNC = [
  'fc.assert(fc.property(arb, () => {}));',
  'await fc.assert(fc.asyncProperty(arb, async () => {}));',
].join('\n');

const AWAITED_PROMISE_ALL = [
  'await Promise.all([',
  '  fc.assert(fc.asyncProperty(arb, async () => {})),',
  '  fc.assert(fc.asyncProperty(arb, async () => {})),',
  ']);',
].join('\n');

describe('async property assertions are awaited', () => {
  it('finds no unawaited fc.assert over an async property', () => {
    const offenders = testFiles(TEST_DIR).flatMap((file) =>
      unawaitedAsyncAssertions(readFileSync(file, 'utf8'), file.slice(TEST_DIR.length)),
    );

    expect(offenders).toEqual([]);
  });

  // A guard is worth exactly what it can see, so it is shown the mistake and its correction. The
  // position reported is the property, not the assert, because that is the site being scanned.
  it('sees the mistake when it is there', () => {
    expect(unawaitedAsyncAssertions(ASYNC_ASSERTION, 'sample.ts')).toEqual(['sample.ts:2']);
    expect(unawaitedAsyncAssertions(`await ${ASYNC_ASSERTION}`, 'sample.ts')).toEqual([]);
  });

  it('does not object to a synchronous property left unawaited', () => {
    expect(unawaitedAsyncAssertions(SYNC_ASSERTION, 'sample.ts')).toEqual([]);
  });

  // Hoisting the property past the assert defeats any check that reads the assert call alone. It
  // is refused rather than resolved: following the variable would mean tracking assignments, and
  // inlining the property into its assert costs nothing.
  it('flags a property hoisted out of its assert', () => {
    expect(unawaitedAsyncAssertions(HOISTED_UNAWAITED, 'sample.ts')).toEqual(['sample.ts:1']);
  });

  // A fixed lookahead makes the guard a function of how much prose sits between the two calls.
  it('flags an async property however much comment precedes it', () => {
    expect(unawaitedAsyncAssertions(LONG_COMMENT_BEFORE, 'sample.ts')).toEqual(['sample.ts:3']);
  });

  // The mirror image: a synchronous assert must not inherit the blame for an awaited async one
  // that happens to sit near it.
  it('does not blame a sync assert for the async one after it', () => {
    expect(unawaitedAsyncAssertions(SYNC_THEN_AWAITED_ASYNC, 'sample.ts')).toEqual([]);
  });

  // Running properties concurrently is legitimate and the await is on the combinator, not on each
  // assert. Requiring `await fc.assert` literally would have banned it.
  it('accepts asserts awaited through a combinator', () => {
    expect(unawaitedAsyncAssertions(AWAITED_PROMISE_ALL, 'sample.ts')).toEqual([]);
  });
});
