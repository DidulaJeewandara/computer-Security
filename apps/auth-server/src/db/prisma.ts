import { PrismaClient } from '@prisma/client';
import type { Config } from '../config.js';
// Explicitly inject configuration; do not let Prisma resolve an environment URL.
export function createDatabase(config: Pick<Config, 'databaseUrl'>) {
  return new PrismaClient({ datasourceUrl: config.databaseUrl, log: [] });
}
let singleton: PrismaClient | undefined;
export function getDatabase(config: Pick<Config, 'databaseUrl'>) {
  singleton ??= createDatabase(config);
  return singleton;
}
