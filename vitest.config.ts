import { defineConfig } from 'vitest/config';
// Comment-only teammate test placeholders are not executable suites.
export default defineConfig({
  test: {
    include: [
      'packages/protocol/src/{encode,types}.test.ts',
      'apps/auth-server/src/tls.test.ts',
      'apps/auth-server/src/config.test.ts',
      'apps/auth-server/src/app.test.ts',
      'apps/auth-server/src/db/userService.test.ts',
      'apps/auth-server/src/db/database.integration.test.ts',
      'tests/platform/*.integration.test.ts',
    ],
    testTimeout: 15000,
  },
});
