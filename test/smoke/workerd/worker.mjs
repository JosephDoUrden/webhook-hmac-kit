/**
 * The smoke checks on workerd, the runtime under Cloudflare Workers.
 *
 * `workerd test config.capnp` calls the `test()` export below and exits non-zero if it throws, so
 * there is no server, no port and no request to send. config.capnp turns nodejs_compat off, which
 * takes node:assert away with the rest of Node, so the assert handed to smoke-core.mjs is the
 * small one here, built on plain `throw`. It only has to cover what smoke-core.mjs calls.
 *
 * workerd needs every module listed in its config and dist/ is split into hashed chunks, so this
 * file is bundled into worker.bundle.mjs first:
 *
 *   npm run build
 *   npm run --prefix test/smoke/workerd bundle
 *   npx --prefix test/smoke/workerd workerd test test/smoke/workerd/config.capnp
 */

import { verifyStandardWebhooksRequest } from '../../../dist/adapters/web.js';
import {
  WebCryptoUnavailableError,
  WebhookError,
  signWebhook,
  verifyWebhook,
} from '../../../dist/index.js';
import { runSmoke } from '../smoke-core.mjs';

const fail = (message, fallback) => {
  throw new Error(message ?? fallback);
};

const assert = {
  ok(value, message) {
    if (!value) fail(message, `expected a truthy value, got ${value}`);
  },
  equal(actual, expected, message) {
    if (!Object.is(actual, expected)) fail(message, `expected ${expected}, got ${actual}`);
  },
  // Enough for the plain objects smoke-core.mjs compares; key order counts.
  deepEqual(actual, expected, message) {
    const a = JSON.stringify(actual);
    const b = JSON.stringify(expected);
    if (a !== b) fail(message, `expected ${b}, got ${a}`);
  },
  match(string, pattern, message) {
    if (!pattern.test(string)) fail(message, `expected ${pattern} to match ${string}`);
  },
  throws(fn, pattern, message) {
    try {
      fn();
    } catch (error) {
      if (!pattern.test(error?.message)) fail(message, `wrong error: ${error?.message}`);
      return;
    }
    fail(message, 'expected a throw');
  },
  async rejects(promise, check, message) {
    try {
      await promise;
    } catch (error) {
      if (check(error) !== true) fail(message, `wrong rejection: ${error?.message}`);
      return;
    }
    fail(message, 'expected a rejection');
  },
};

export default {
  async test() {
    const summary = await runSmoke({
      assert,
      signWebhook,
      verifyWebhook,
      WebhookError,
      WebCryptoUnavailableError,
      verifyStandardWebhooksRequest,
    });
    console.log(`smoke ok on ${navigator.userAgent}: ${summary}`);
  },
};
