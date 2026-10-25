/**
 * Runs the built package on whichever runtime is executing this file.
 *
 * A plain script, not a vitest suite: vitest only runs on Node, and the whole point of the Web
 * Crypto migration is the runtimes it does not run on. node:assert/strict is the one testing API
 * that Node, Deno and Bun all have, so one file covers all three with no flags and no config.
 *
 *   node test/smoke/smoke.mjs
 *   deno run test/smoke/smoke.mjs
 *   bun  test/smoke/smoke.mjs
 *
 * It imports from dist/, so `npm run build` has to have run. That is deliberate — the thing worth
 * smoking is the artefact that gets published, including whatever tsup did to the specifiers on
 * the way out.
 *
 * The checks live in smoke-core.mjs so that workerd/worker.mjs can run the same ones on workerd,
 * which has no node:assert once nodejs_compat is off.
 */

import assert from 'node:assert/strict';
import { verifyStandardWebhooksRequest } from '../../dist/adapters/web.js';
import {
  WebCryptoUnavailableError,
  WebhookError,
  signWebhook,
  verifyWebhook,
} from '../../dist/index.js';
import { runSmoke } from './smoke-core.mjs';

const summary = await runSmoke({
  assert,
  signWebhook,
  verifyWebhook,
  WebhookError,
  WebCryptoUnavailableError,
  verifyStandardWebhooksRequest,
});

const runtime =
  typeof Deno !== 'undefined'
    ? `Deno ${Deno.version.deno}`
    : typeof Bun !== 'undefined'
      ? `Bun ${Bun.version}`
      : `Node ${globalThis.process.versions.node}`;

console.log(`smoke ok on ${runtime}: ${summary}`);
