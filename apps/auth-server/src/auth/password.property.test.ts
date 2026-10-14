// [JDH] P1-JDH-2: property tests for the Argon2id service — unique salts, correct verify, tamper fails, rehash only when stale
import { randomBytes } from 'node:crypto';
import fc from 'fast-check';
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
import { normalizePassword } from './passwordPolicy.js';

// Low-cost parameters keep a few hundred hashes fast. A handful of cases also run at
// CURRENT_PARAMS so the real parameters are exercised too.
const CHEAP: Argon2Params = {
  memoryKib: 64,
  iterations: 1,
  parallelism: 1,
  saltBytes: 16,
  tagBytes: 32,
};

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64').replace(/=+$/, '');
const phc = (p: Argon2Params, salt: Uint8Array, tag: Uint8Array) =>
  `$argon2id$v=19$m=${p.memoryKib},t=${p.iterations},p=${p.parallelism}$${b64(salt)}$${b64(tag)}`;

// Passwords as users type them: any Unicode, spaces included, no lone surrogates.
const password = fc.string({ unit: 'grapheme', minLength: 1, maxLength: 40 });

/** A tampered hash must never verify: it either verifies false or is rejected as malformed. */
async function rejects(pw: string, encoded: string): Promise<boolean> {
  try {
    return (await verifyPassword(pw, encoded)) === false;
  } catch (e) {
    return e instanceof PasswordHashFormatError;
  }
}

describe('salts', () => {
  it('are unique across many hashes of the same password', async () => {
    const hashes = await Promise.all(
      Array.from({ length: 200 }, () => hashPassword('same password', CHEAP)),
    );
    const salts = hashes.map((h) => parseHash(h).salt.toString('hex'));
    expect(new Set(salts).size).toBe(hashes.length);
    expect(new Set(hashes).size).toBe(hashes.length);
    for (const h of hashes) expect(parseHash(h).saltBytes).toBe(16);
  });

  it('are unique at the real parameters too', async () => {
    const hashes = await Promise.all(
      Array.from({ length: 5 }, () => hashPassword('same password')),
    );
    expect(new Set(hashes.map((h) => parseHash(h).salt.toString('hex'))).size).toBe(5);
  });
});

describe('verification', () => {
  it('accepts the password that made the hash, for any Unicode password', async () => {
    await fc.assert(
      fc.asyncProperty(password, async (pw) => {
        expect(await verifyPassword(pw, await hashPassword(pw, CHEAP))).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('rejects any password that is not the same after normalisation', async () => {
    await fc.assert(
      fc.asyncProperty(password, password, async (pw, other) => {
        fc.pre(normalizePassword(pw) !== normalizePassword(other));
        expect(await verifyPassword(other, await hashPassword(pw, CHEAP))).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  it('accepts and rejects correctly at the real parameters', async () => {
    const h = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', h)).toBe(true);
    expect(await verifyPassword('correct horse battery stapler', h)).toBe(false);
  });
});

describe('tampering with any part of the encoded hash', () => {
  it('never verifies, whichever single character is changed', async () => {
    const pw = 'tamper target passphrase';
    const encoded = await hashPassword(pw, CHEAP);
    await fc.assert(
      fc.asyncProperty(
        fc.nat({ max: encoded.length - 1 }),
        fc.constantFrom(...B64, '$', ',', '=', '-'),
        async (i, ch) => {
          fc.pre(encoded[i] !== ch);
          expect(await rejects(pw, encoded.slice(0, i) + ch + encoded.slice(i + 1))).toBe(true);
        },
      ),
      { numRuns: 300 },
    );
  });

  it('never verifies when the salt or tag is replaced, truncated or extended', async () => {
    const pw = 'tamper target passphrase';
    const encoded = await hashPassword(pw, CHEAP);
    const [, , , params, salt, tag] = encoded.split('$') as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    const variants = [
      [params, b64(randomBytes(16)), tag],
      [params, salt, b64(randomBytes(32))],
      [params, salt.slice(0, -4), tag],
      [params, salt, tag.slice(0, -4)],
      [params, salt + 'AAAA', tag],
      [params, salt, tag + 'AAAA'],
      [params, tag, salt],
    ];
    for (const [p, s, t] of variants) {
      expect(await rejects(pw, `$argon2id$v=19$${p}$${s}$${t}`)).toBe(true);
    }
  });

  it('never verifies when a cost parameter is changed', async () => {
    const pw = 'tamper target passphrase';
    const encoded = await hashPassword(pw, CHEAP);
    const { salt, tag } = parseHash(encoded);
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          memoryKib: fc.integer({ min: 8, max: 256 }),
          iterations: fc.integer({ min: 1, max: 3 }),
          parallelism: fc.integer({ min: 1, max: 2 }),
        }),
        async (p) => {
          fc.pre(
            p.memoryKib !== CHEAP.memoryKib ||
              p.iterations !== CHEAP.iterations ||
              p.parallelism !== CHEAP.parallelism,
          );
          expect(await rejects(pw, phc({ ...CHEAP, ...p }, salt, tag))).toBe(true);
        },
      ),
      { numRuns: 60 },
    );
  });

  it('never verifies when the algorithm or version label is changed', async () => {
    const pw = 'tamper target passphrase';
    const encoded = await hashPassword(pw, CHEAP);
    for (const bad of [
      encoded.replace('$argon2id$', '$argon2i$'),
      encoded.replace('$argon2id$', '$argon2d$'),
      encoded.replace('$v=19$', '$v=16$'),
      encoded.replace('$v=19$', '$'),
    ]) {
      expect(await rejects(pw, bad)).toBe(true);
    }
  });
});

describe('rehash on login', () => {
  const params = fc.record({
    memoryKib: fc.constantFrom(8192, 9216, 19456, 47104, 65536),
    iterations: fc.constantFrom(1, 2, 3),
    parallelism: fc.constantFrom(1, 2),
    saltBytes: fc.constantFrom(8, 16, 32),
    tagBytes: fc.constantFrom(16, 32, 64),
  });
  const same = (p: Argon2Params) =>
    p.memoryKib === CURRENT_PARAMS.memoryKib &&
    p.iterations === CURRENT_PARAMS.iterations &&
    p.parallelism === CURRENT_PARAMS.parallelism &&
    p.saltBytes === CURRENT_PARAMS.saltBytes &&
    p.tagBytes === CURRENT_PARAMS.tagBytes;

  it('is needed exactly when any stored parameter differs from the current ones', () => {
    fc.assert(
      fc.property(params, (p) => {
        const encoded = phc(p, randomBytes(p.saltBytes), randomBytes(p.tagBytes));
        expect(needsRehash(encoded)).toBe(!same(p));
      }),
      { numRuns: 500 },
    );
    expect(needsRehash(phc(CURRENT_PARAMS, randomBytes(16), randomBytes(32)))).toBe(false);
  });

  it('saves a new hash only after a correct password on a stale hash', async () => {
    const pw = 'rehash target passphrase';
    const stale = await hashPassword(pw, CHEAP);
    const current = await hashPassword(pw);
    const cases: [string, string, boolean][] = [
      [pw, stale, true],
      ['wrong passphrase', stale, false],
      [pw, current, false],
      ['wrong passphrase', current, false],
    ];
    for (const [attempt, stored, shouldSave] of cases) {
      const save = vi.fn(async () => {});
      await verifyAndUpgrade(attempt, stored, save);
      expect(save).toHaveBeenCalledTimes(shouldSave ? 1 : 0);
      if (shouldSave) {
        const saved = (save.mock.calls[0] as unknown as [string])[0];
        expect(needsRehash(saved)).toBe(false);
        expect(await verifyPassword(pw, saved)).toBe(true);
      }
    }
  });
});
