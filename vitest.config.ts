import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    // crypto.subtle is one object for the whole process, so a spy left on it by one file is still
    // there for the next. Restoring after every test keeps the call-count assertions in
    // rotation.test.ts measuring their own work and nobody else's.
    restoreMocks: true,
    coverage: {
      provider: 'v8',
    },
  },
});
