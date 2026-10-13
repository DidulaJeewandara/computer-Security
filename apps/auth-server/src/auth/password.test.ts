// [JDH] Unique salts; tamper fails; rehash only when parameters are stale; verify-time benchmark
import { timingSafeEqual } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  CURRENT_PARAMS,
  PasswordHashFormatError,
  hashPassword,
  needsRehash,
  parseHash,
  verifyAndUpgrade,
  verifyPassword,
  type Argon2Params,
} from './password.js';

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

const PASSWORD = 'correct horse battery staple';
const WEAK: Argon2Params = {
  memoryKib: 8192,
  iterations: 1,
  parallelism: 1,
  saltBytes: 16,
  tagBytes: 32,
};

// swap the first character of a segment so the decoded bytes really change
const swapFirst = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);

describe('hashPassword', () => {
  it('uses the shared-context parameters and a 16-byte salt', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(hash.startsWith('$argon2id$v=19$m=19456,t=2,p=1$')).toBe(true);
    const parsed = parseHash(hash);
    expect(parsed.salt.length).toBe(16);
    expect(parsed.tag.length).toBe(32);
  });

  it('gives a different salt and hash each time', async () => {
    const [a, b] = await Promise.all([hashPassword(PASSWORD), hashPassword(PASSWORD)]);
    expect(a).not.toBe(b);
    expect(parseHash(a).salt.equals(parseHash(b).salt)).toBe(false);
  });
});

describe('verifyPassword', () => {
  it('accepts the right password and rejects a wrong one', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword(PASSWORD, hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
  });

  it('compares with timingSafeEqual', async () => {
    const hash = await hashPassword(PASSWORD);
    vi.mocked(timingSafeEqual).mockClear();
    await verifyPassword(PASSWORD, hash);
    expect(timingSafeEqual).toHaveBeenCalledTimes(1);
  });

  it('fails when the tag, salt or a parameter is tampered with', async () => {
    const hash = await hashPassword(PASSWORD);
    const [, , , params, salt, tag] = hash.split('$') as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    const rebuild = (p: string, s: string, t: string) => `$argon2id$v=19$${p}$${s}$${t}`;
    expect(await verifyPassword(PASSWORD, rebuild(params, salt, swapFirst(tag)))).toBe(false);
    expect(await verifyPassword(PASSWORD, rebuild(params, swapFirst(salt), tag))).toBe(false);
    expect(await verifyPassword(PASSWORD, rebuild(params.replace('t=2', 't=3'), salt, tag))).toBe(
      false,
    );
  });

  it('rejects non-canonical base64 instead of treating it as the same hash', async () => {
    const hash = await hashPassword(PASSWORD);
    // a 32-byte tag is 43 chars, so the last char carries 2 unused (zero) bits; set one of them
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const alt = alphabet[alphabet.indexOf(hash.at(-1)!) | 1]!;
    await expect(verifyPassword(PASSWORD, hash.slice(0, -1) + alt)).rejects.toBeInstanceOf(
      PasswordHashFormatError,
    );
  });
});

describe('unicode normalisation', () => {
  it('verifies the same password typed as NFC or NFD against one hash', async () => {
    const nfc = 'caf\u00e9 au lait';
    const nfd = 'cafe\u0301 au lait';
    expect(nfc).not.toBe(nfd);
    const hash = await hashPassword(nfc);
    expect(await verifyPassword(nfd, hash)).toBe(true);
  });
});

describe('stored hash parsing', () => {
  const bad = [
    '',
    'not a hash',
    '$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=16$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=19$m=4294967295,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=19$m=19456,t=999999,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=19$m=19456,t=2,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=19$m=8,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    '$argon2id$v=19$m=19456,t=2,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  ];

  it.each(bad)('throws a format error for %j without echoing it', async (value) => {
    const err = await verifyPassword(PASSWORD, value).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PasswordHashFormatError);
    if (value) expect((err as Error).message).not.toContain(value);
  });
});

describe('needsRehash', () => {
  it('is false for a current hash and true for weaker ones', async () => {
    expect(needsRehash(await hashPassword(PASSWORD))).toBe(false);
    expect(needsRehash(await hashPassword(PASSWORD, WEAK))).toBe(true);
    expect(needsRehash(await hashPassword(PASSWORD, { ...CURRENT_PARAMS, iterations: 1 }))).toBe(
      true,
    );
    expect(needsRehash(await hashPassword(PASSWORD, { ...CURRENT_PARAMS, saltBytes: 8 }))).toBe(
      true,
    );
  });
});

describe('verifyAndUpgrade', () => {
  it('upgrades a weaker hash at the next successful login and changes the stored parameters', async () => {
    let stored = await hashPassword(PASSWORD, WEAK);
    const before = parseHash(stored);
    expect(before.memoryKib).toBe(8192);
    expect(before.iterations).toBe(1);

    const save = vi.fn(async (h: string) => {
      stored = h;
    });
    expect(await verifyAndUpgrade(PASSWORD, stored, save)).toBe(true);

    const after = parseHash(stored);
    expect(save).toHaveBeenCalledTimes(1);
    expect(after.memoryKib).toBe(CURRENT_PARAMS.memoryKib);
    expect(after.iterations).toBe(CURRENT_PARAMS.iterations);
    expect(after.parallelism).toBe(CURRENT_PARAMS.parallelism);
    expect(after.memoryKib).not.toBe(before.memoryKib);
    expect(after.salt.equals(before.salt)).toBe(false);
    expect(needsRehash(stored)).toBe(false);
    expect(await verifyPassword(PASSWORD, stored)).toBe(true);
  });

  it('does not save anything after a wrong password', async () => {
    const stored = await hashPassword(PASSWORD, WEAK);
    const save = vi.fn(async () => {});
    expect(await verifyAndUpgrade('wrong password', stored, save)).toBe(false);
    expect(save).not.toHaveBeenCalled();
  });

  it('does not save when the hash is already current', async () => {
    const stored = await hashPassword(PASSWORD);
    const save = vi.fn(async () => {});
    expect(await verifyAndUpgrade(PASSWORD, stored, save)).toBe(true);
    expect(save).not.toHaveBeenCalled();
  });

  it('lets a failed save surface instead of hiding it', async () => {
    const stored = await hashPassword(PASSWORD, WEAK);
    const save = vi.fn(async () => {
      throw new Error('db down');
    });
    await expect(verifyAndUpgrade(PASSWORD, stored, save)).rejects.toThrow('db down');
  });
});
