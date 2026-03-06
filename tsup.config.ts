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
  external: ['node:crypto', 'express', 'fastify', '@nestjs/common'],
});
