import { randomBytes } from 'node:crypto';
import { argon2id, hash } from 'argon2';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
const seedInput = z
  .object({ username: z.string().min(1).max(128), password: z.string().min(8).max(1024) })
  .strict();
export async function createSeedUser(
  db: PrismaClient,
  input: { username: string; password: string },
) {
  const parsed = seedInput.safeParse(input);
  if (!parsed.success) throw new Error('SEED_INPUT_INVALID');
  const existing = await db.user.findUnique({ where: { username: parsed.data.username } });
  if (existing) return existing;
  const encoded = await hash(parsed.data.password, {
    type: argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
    salt: randomBytes(16),
  });
  return db.user.create({
    data: {
      username: parsed.data.username,
      passwordCredential: {
        create: { hash: encoded, memoryKiB: 19456, timeCost: 2, parallelism: 1 },
      },
    },
  });
}
