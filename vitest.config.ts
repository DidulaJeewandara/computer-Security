import { defineConfig } from 'vitest/config';
// Comment-only teammate test placeholders are not executable suites.
export default defineConfig({
  test: {
    include: [
      'packages/protocol/src/{encode,types}.test.ts',
      'apps/auth-server/src/tls.test.ts',
      'tests/udk/**/*.test.ts',
    ],
    testTimeout: 15000,
  },
});
