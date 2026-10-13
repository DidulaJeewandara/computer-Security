import { ConfigError, loadConfig, loadSeedConfig } from '../apps/auth-server/src/config.js';
import { createDatabase } from '../apps/auth-server/src/db/prisma.js';
import { createSeedUser } from '../apps/auth-server/src/db/seed.js';
async function seed() {
  const config = loadConfig();
  const input = loadSeedConfig();
  const db = createDatabase(config);
  try {
    await createSeedUser(db, input);
  } finally {
    await db.$disconnect();
  }
}
seed().catch((error) => {
  console.error(error instanceof ConfigError ? `${error.name}: ${error.message}` : 'SEED_FAILED');
  process.exitCode = 1;
});
