// [RMR] Argon2id m=19456 KiB t=2 p=1, 16-byte salt, rehash-on-login, constant-time compare
import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { z } from 'zod';
import { NOTATION } from '@deltaforce/protocol';
import { normalizePassword } from './passwordPolicy.js';

const argon2Async = promisify(argon2);

export interface Argon2Params {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  saltBytes: number;
  tagBytes: number;
}

const A = NOTATION.ARGON2ID;

export const CURRENT_PARAMS: Readonly<Argon2Params> = Object.freeze({
  memoryKib: A.MEMORY_KIB,
  iterations: A.ITERATIONS,
  parallelism: A.PARALLELISM,
  saltBytes: A.SALT_BYTES,
  tagBytes: 32, // RFC 9106 recommended tag length, not fixed by the shared context
});

export class PasswordHashFormatError extends Error {
  constructor() {
    // never echo the stored hash
    super('PASSWORD_HASH_FORMAT: stored password hash is malformed or out of bounds');
    this.name = 'PasswordHashFormatError';
  }
}

// Our own caps so a tampered row can't make us allocate without limit.
const ParsedHashSchema = z.object({
  memoryKib: z.number().int().min(8).max(1_048_576),
  iterations: z.number().int().min(1).max(16),
  parallelism: z.number().int().min(1).max(16),
  salt: z.instanceof(Uint8Array).refine((b) => b.length >= 8 && b.length <= 64),
  tag: z.instanceof(Uint8Array).refine((b) => b.length >= 16 && b.length <= 64),
});

const PHC =
  /^\$argon2id\$v=19\$m=(0|[1-9]\d*),t=(0|[1-9]\d*),p=(0|[1-9]\d*)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

const encodeB64 = (b: Uint8Array) => Buffer.from(b).toString('base64').replace(/=+$/, '');

// Rejects non-canonical base64, so changing the unused trailing bits can't pass as the same hash.
function decodeB64(s: string): Buffer {
  const bytes = Buffer.from(s, 'base64');
  if (encodeB64(bytes) !== s) throw new PasswordHashFormatError();
  return bytes;
}

export interface ParsedHash extends Argon2Params {
  salt: Buffer;
  tag: Buffer;
}

export function parseHash(encoded: string): ParsedHash {
  const m = PHC.exec(encoded);
  if (!m) throw new PasswordHashFormatError();
  const salt = decodeB64(m[4]!);
  const tag = decodeB64(m[5]!);
  const parsed = ParsedHashSchema.safeParse({
    memoryKib: Number(m[1]),
    iterations: Number(m[2]),
    parallelism: Number(m[3]),
    salt,
    tag,
  });
  if (!parsed.success || parsed.data.memoryKib < 8 * parsed.data.parallelism) {
    throw new PasswordHashFormatError();
  }
  return {
    memoryKib: parsed.data.memoryKib,
    iterations: parsed.data.iterations,
    parallelism: parsed.data.parallelism,
    saltBytes: salt.length,
    tagBytes: tag.length,
    salt,
    tag,
  };
}

function derive(password: string, salt: Uint8Array, p: Argon2Params): Promise<Buffer> {
  return argon2Async('argon2id', {
    message: Buffer.from(normalizePassword(password), 'utf8'),
    nonce: salt,
    memory: p.memoryKib,
    passes: p.iterations,
    parallelism: p.parallelism,
    tagLength: p.tagBytes,
  });
}

function encode(p: Argon2Params, salt: Uint8Array, tag: Uint8Array): string {
  return `$argon2id$v=19$m=${p.memoryKib},t=${p.iterations},p=${p.parallelism}$${encodeB64(salt)}$${encodeB64(tag)}`;
}

/** `params` is only for tests and the benchmark; production callers use the default. */
export async function hashPassword(
  password: string,
  params: Argon2Params = CURRENT_PARAMS,
): Promise<string> {
  const salt = randomBytes(params.saltBytes);
  return encode(params, salt, await derive(password, salt, params));
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const stored = parseHash(encoded);
  const tag = await derive(password, stored.salt, stored);
  return timingSafeEqual(tag, stored.tag);
}

export function needsRehash(encoded: string, params: Argon2Params = CURRENT_PARAMS): boolean {
  const s = parseHash(encoded);
  return (
    s.memoryKib !== params.memoryKib ||
    s.iterations !== params.iterations ||
    s.parallelism !== params.parallelism ||
    s.saltBytes !== params.saltBytes ||
    s.tagBytes !== params.tagBytes
  );
}

/** Verify, then silently re-hash at current parameters if the stored hash is stale. */
export async function verifyAndUpgrade(
  password: string,
  encoded: string,
  save: (newHash: string) => Promise<void>,
): Promise<boolean> {
  if (!(await verifyPassword(password, encoded))) return false;
  if (needsRehash(encoded)) await save(await hashPassword(password));
  return true;
}
