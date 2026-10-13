import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verify } from 'argon2';
import { integrationEnabled, loadConfig } from '../../../apps/auth-server/src/config.js';
import { createDatabase } from '../../../apps/auth-server/src/db/prisma.js';
import { createSeedUser } from '../../../apps/auth-server/src/db/seed.js';
import { authenticatePassword } from '../../../apps/auth-server/src/db/userService.js';

const enabled = integrationEnabled();
describe.skipIf(!enabled)('P1-UDK-1 PostgreSQL acceptance', () => {
  const schema = `udk_test_${randomUUID().replaceAll('-', '')}`;
  let db: ReturnType<typeof createDatabase>;
  beforeAll(async () => {
    const config = loadConfig();
    const url = new URL(config.databaseUrl);
    url.searchParams.set('schema', schema);
    execFileSync(
      'pnpm',
      ['exec', 'prisma', 'migrate', 'deploy', '--schema', 'prisma/schema.prisma'],
      { env: { ...process.env, DATABASE_URL: url.toString() }, stdio: 'pipe' },
    );
    db = createDatabase({ ...config, databaseUrl: url.toString() });
    await db.$connect();
  }, 60000);
  afterAll(async () => {
    if (db) {
      await db.$executeRawUnsafe(`DROP SCHEMA "${schema}" CASCADE`);
      await db.$disconnect();
    }
  });
  it('migrates an empty database and seeds a password-only account that authenticates', async () => {
    const account = await createSeedUser(db, {
      username: 'seed-demo',
      password: 'seed-test-passphrase',
    });
    const credential = await db.passwordCredential.findUniqueOrThrow({
      where: { userId: account.id },
    });
    expect(credential).toMatchObject({ memoryKiB: 19456, timeCost: 2, parallelism: 1 });
    expect(credential.hash).toMatch(/^\$argon2id\$/);
    expect(Buffer.from(credential.hash.split('$')[4]!, 'base64').length).toBe(16);
    expect(await db.authenticator.count({ where: { userId: account.id } })).toBe(0);
    expect(await authenticatePassword(db, 'seed-demo', 'seed-test-passphrase', verify)).toEqual({
      id: account.id,
    });
    expect(await authenticatePassword(db, 'seed-demo', 'wrong', verify)).toBeNull();
    await createSeedUser(db, { username: 'seed-demo', password: 'replacement-not-used' });
    expect(await authenticatePassword(db, 'seed-demo', 'seed-test-passphrase', verify)).toEqual({
      id: account.id,
    });
  });
  it('database rejects audit-event updates and deletes', async () => {
    const event = await db.authEvent.create({
      data: { eventType: 'handshake_started', prevHash: null },
    });
    await expect(
      db.authEvent.update({ where: { id: event.id }, data: { eventType: 'tampered' } }),
    ).rejects.toThrow();
    await expect(db.authEvent.delete({ where: { id: event.id } })).rejects.toThrow();
    expect((await db.authEvent.findUniqueOrThrow({ where: { id: event.id } })).eventType).toBe(
      'handshake_started',
    );
  });
  it('all required durable tables exist', async () => {
    const rows = await db.$queryRaw<
      Array<{ table_name: string }>
    >`SELECT table_name FROM information_schema.tables WHERE table_schema = ${schema}`;
    expect(rows.map((row) => row.table_name)).toEqual(
      expect.arrayContaining([
        'users',
        'password_credentials',
        'authenticators',
        'recovery_codes',
        'auth_events',
        'sessions',
      ]),
    );
  });
});
