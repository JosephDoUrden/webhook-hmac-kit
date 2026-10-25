import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: [
      'src/index.ts',
      'src/adapters/express.ts',
      'src/adapters/fastify.ts',
      'src/adapters/nest.ts',
      'src/adapters/web.ts',
      'src/adapters/hono.ts',
    ],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    // The two configs build in parallel into one folder. This one cleans it, and leaves the CLI's
    // output alone so a slow library build cannot delete a CLI that finished first.
    clean: ['!cli.js', '!cli.js.map'],
    minify: false,
    noExternal: [],
    // tsup 8 rewrites `node:crypto` to bare `crypto` by default, which is why the `node:crypto`
    // entry that used to sit in `external` never had any effect: by the time esbuild resolved the
    // import the specifier no longer matched. A bare builtin does not resolve on Deno or on a
    // bundler configured for the browser, so the rewrite is off for good, not just for this release.
    removeNodeProtocol: false,
    // platform stays at tsup's default 'node'. 'neutral' drops esbuild's cjs-module-lexer
    // annotation, and Node then throws "Named export not found" on `import { signWebhook }` from
    // the CJS build.
    external: ['express', 'fastify', '@nestjs/common'],
  },
  // The CLI, from cli/ because src/ stays free of `node:` imports. ESM only, no declarations, and
  // a shebang so npm can link it as a bin. Its `../src/index.js` import becomes a runtime import
  // of the library build next to it, so the binary checks the code a caller actually gets; the
  // corpus JSON is bundled in.
  {
    entry: { cli: 'cli/cli.ts' },
    format: ['esm'],
    dts: false,
    sourcemap: true,
    clean: false,
    minify: false,
    removeNodeProtocol: false,
    banner: { js: '#!/usr/bin/env node' },
    esbuildPlugins: [
      {
        name: 'library-stays-external',
        setup(build) {
          build.onResolve({ filter: /^\.\.\/src\/index\.js$/ }, () => ({
            path: './index.js',
            external: true,
          }));
        },
      },
    ],
  },
]);
