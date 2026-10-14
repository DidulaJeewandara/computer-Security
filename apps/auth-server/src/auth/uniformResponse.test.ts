// [JDH] Two hundred requests cannot separate unknown user from wrong password
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { hashPassword, needsRehash, type Argon2Params } from './password.js';
import {
  AUTH_FAILURE,
  MIN_AUTH_RESPONSE_MS,
  checkPasswordUniformly,
  dummyPasswordHash,
  warmUp,
  withMinimumDuration,
  type PasswordCheckDeps,
} from './uniformResponse.js';

const PASSWORD = 'correct horse battery staple';
let aliceHash: string;

function deps(overrides: Partial<PasswordCheckDeps> = {}): PasswordCheckDeps {
  return {
    findPasswordHash: async (u) => (u === 'alice' ? aliceHash : null),
    savePasswordHash: async () => {},
    ...overrides,
  };
}

beforeAll(async () => {
  aliceHash = await hashPassword(PASSWORD);
  await warmUp();
});

describe('responses', () => {
  it('accepts the right password for a known user', async () => {
    expect(await checkPasswordUniformly(deps(), 'alice', PASSWORD)).toEqual({ ok: true });
  });

  it('returns byte-identical failures for an unknown user and a wrong password', async () => {
    const unknown = await checkPasswordUniformly(deps(), 'mallory', PASSWORD);
    const wrong = await checkPasswordUniformly(deps(), 'alice', 'wrong horse battery staple');
    expect(unknown).toEqual({ ok: false, response: AUTH_FAILURE });
    expect(wrong).toEqual({ ok: false, response: AUTH_FAILURE });
    if (unknown.ok || wrong.ok) throw new Error('unreachable');
    expect(unknown.response.status).toBe(wrong.response.status);
    expect(Buffer.from(unknown.response.body)).toEqual(Buffer.from(wrong.response.body));
    expect(unknown.response.headers).toEqual(wrong.response.headers);
  });

  it('never accepts the dummy hash, even if someone guessed its password', async () => {
    // The unknown-user path verifies against the dummy hash; a match must still fail.
    const result = await checkPasswordUniformly(
      deps({ findPasswordHash: async () => null }),
      'mallory',
      PASSWORD,
    );
    expect(result.ok).toBe(false);
  });

  it('answers a corrupted stored hash exactly like a wrong password', async () => {
    const result = await checkPasswordUniformly(
      deps({ findPasswordHash: async () => '$argon2id$v=19$m=1,t=1,p=1$AAAA$AAAA' }),
      'alice',
      PASSWORD,
    );
    expect(result).toEqual({ ok: false, response: AUTH_FAILURE });
  });

  it('says nothing about the account, the password or the reason', () => {
    expect(AUTH_FAILURE.body).toBe('{"code":"AUTH_FAILED"}');
    expect(AUTH_FAILURE.status).toBe(401);
  });

  it('still upgrades a stale hash after a correct password', async () => {
    const weak: Argon2Params = {
      memoryKib: 8192,
      iterations: 1,
      parallelism: 1,
      saltBytes: 16,
      tagBytes: 32,
    };
    const stale = await hashPassword(PASSWORD, weak);
    const save = vi.fn(async () => {});
    const result = await checkPasswordUniformly(
      deps({ findPasswordHash: async () => stale, savePasswordHash: save }),
      'alice',
      PASSWORD,
    );
    expect(result.ok).toBe(true);
    expect(save).toHaveBeenCalledTimes(1);
    expect(needsRehash((save.mock.calls[0] as unknown as [string, string])[1])).toBe(false);
  });

  it('never saves a hash on the unknown-user path', async () => {
    const save = vi.fn(async () => {});
    await checkPasswordUniformly(deps({ savePasswordHash: save }), 'mallory', PASSWORD);
    expect(save).not.toHaveBeenCalled();
  });

  it('uses a dummy hash at the current Argon2id parameters, so the work is the same', async () => {
    expect(needsRehash(await dummyPasswordHash())).toBe(false);
  });
});

describe('minimum duration', () => {
  it('holds a fast success and a fast failure to the floor', async () => {
    const t0 = performance.now();
    await withMinimumDuration(async () => 1, 50);
    expect(performance.now() - t0).toBeGreaterThanOrEqual(49);
    const t1 = performance.now();
    await expect(
      withMinimumDuration(async () => {
        throw new Error('boom');
      }, 50),
    ).rejects.toThrow('boom');
    expect(performance.now() - t1).toBeGreaterThanOrEqual(49);
  });

  it('applies to every password check', async () => {
    const t0 = performance.now();
    await checkPasswordUniformly(deps(), 'mallory', PASSWORD);
    expect(performance.now() - t0).toBeGreaterThanOrEqual(MIN_AUTH_RESPONSE_MS - 1);
  });
});

describe('timing over two hundred requests', () => {
  /**
   * Best accuracy any single threshold achieves at telling the two groups apart.
   * 0.5 is a coin toss; a real timing leak pushes it towards 1.
   */
  function bestThresholdAccuracy(a: number[], b: number[]): number {
    const all = [...a.map((t) => ({ t, a: true })), ...b.map((t) => ({ t, a: false }))].sort(
      (x, y) => x.t - y.t,
    );
    let best = 0.5;
    let aBelow = 0;
    let bBelow = 0;
    for (const s of all) {
      if (s.a) aBelow++;
      else bBelow++;
      // "at or below the threshold means group a", and its mirror
      const acc = (aBelow + (b.length - bBelow)) / all.length;
      best = Math.max(best, acc, 1 - acc);
    }
    return best;
  }

  async function measure(username: string, password: string): Promise<number> {
    const t0 = performance.now();
    const result = await checkPasswordUniformly(deps(), username, password);
    const elapsed = performance.now() - t0;
    expect(result).toEqual({ ok: false, response: AUTH_FAILURE });
    return elapsed;
  }

  it('cannot separate unknown user from wrong password', async () => {
    const unknown: number[] = [];
    const wrong: number[] = [];
    // 100 of each, interleaved in batches so load affects both groups equally.
    for (let batch = 0; batch < 10; batch++) {
      const runs = Array.from({ length: 20 }, (_, i) =>
        i % 2 === 0
          ? measure(`nobody-${batch}-${i}`, PASSWORD).then((t) => unknown.push(t))
          : measure('alice', `wrong password ${batch}-${i}`).then((t) => wrong.push(t)),
      );
      await Promise.all(runs);
    }
    expect(unknown).toHaveLength(100);
    expect(wrong).toHaveLength(100);
    const accuracy = bestThresholdAccuracy(unknown, wrong);
    // Generous bound so scheduler noise cannot fail CI; an unpadded leak scores near 1.0.
    expect(accuracy).toBeLessThan(0.7);
  }, 60_000);

  it('the same classifier does catch a leak when one exists (control)', () => {
    const fast = Array.from({ length: 100 }, (_, i) => 1 + (i % 3));
    const slow = Array.from({ length: 100 }, (_, i) => 25 + (i % 3));
    expect(bestThresholdAccuracy(fast, slow)).toBe(1);
  });
});
