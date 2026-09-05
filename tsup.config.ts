import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/adapters/express.ts',
    'src/adapters/fastify.ts',
    'src/adapters/nest.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
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
});
