// [JDH] P1-JDH-2: verify-time benchmark at the shared-context Argon2id parameters
// Run with `pnpm bench:argon2` on the demo machine; record the result in docs/benchmarks/argon2id.md.
import { bench, describe } from 'vitest';
import { hashPassword, verifyPassword } from './password.js';

const PASSWORD = 'correct horse battery staple';
const encoded = await hashPassword(PASSWORD);

describe('Argon2id m=19456 KiB t=2 p=1', () => {
  bench(
    'verifyPassword (correct password)',
    async () => {
      await verifyPassword(PASSWORD, encoded);
    },
    { iterations: 50, warmupIterations: 5 },
  );

  bench(
    'verifyPassword (wrong password)',
    async () => {
      await verifyPassword('wrong horse battery staple', encoded);
    },
    { iterations: 50, warmupIterations: 5 },
  );
});
