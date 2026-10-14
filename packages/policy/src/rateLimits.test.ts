// [JDH] Route handlers contain no limits of their own
// (The handler scan lands with P5-JDH-2; these cover the limiter mechanics used today.)
import { describe, expect, it } from 'vitest';
import {
  ConcurrencyLimiter,
  LimitExceededError,
  RATE_LIMITS,
  TokenBucketLimiter,
} from './rateLimits.js';

function clock(start = 0) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe('TokenBucketLimiter', () => {
  it('allows a burst up to capacity, then refuses with a retry delay', () => {
    const c = clock();
    const l = new TokenBucketLimiter({ capacity: 3, refillPerSecond: 1 }, { now: c.now });
    expect([l.take('a'), l.take('a'), l.take('a')].every((r) => r.ok)).toBe(true);
    expect(l.take('a')).toEqual({ ok: false, retryAfterMs: 1000 });
  });

  it('refills at the sustained rate and never above capacity', () => {
    const c = clock();
    const l = new TokenBucketLimiter({ capacity: 2, refillPerSecond: 0.5 }, { now: c.now });
    l.take('a');
    l.take('a');
    expect(l.take('a').ok).toBe(false);
    c.advance(2000);
    expect(l.take('a').ok).toBe(true);
    expect(l.take('a').ok).toBe(false);
    c.advance(3_600_000);
    expect([l.take('a'), l.take('a'), l.take('a')].map((r) => r.ok)).toEqual([true, true, false]);
  });

  it('keeps keys independent', () => {
    const l = new TokenBucketLimiter({ capacity: 1, refillPerSecond: 0.001 }, { now: () => 0 });
    expect(l.take('a').ok).toBe(true);
    expect(l.take('a').ok).toBe(false);
    expect(l.take('b').ok).toBe(true);
  });

  it('remembers at most maxKeys keys, forgetting the least recently seen', () => {
    const l = new TokenBucketLimiter(
      { capacity: 1, refillPerSecond: 0.001 },
      { maxKeys: 100, now: () => 0 },
    );
    for (let i = 0; i < 100_000; i++) l.take(`ip-${i}`);
    expect(l.size).toBe(100);
    // A key seen recently is still limited
    l.take('hot');
    l.take('hot');
    for (let i = 0; i < 50; i++) l.take(`more-${i}`);
    expect(l.take('hot').ok).toBe(false);
  });
});

describe('ConcurrencyLimiter', () => {
  const gate = () => {
    let open!: () => void;
    const p = new Promise<void>((r) => (open = r));
    return { p, open };
  };

  it('never runs more than the bound at once, and refuses beyond the queue', async () => {
    const l = new ConcurrencyLimiter(2, 1);
    const g = gate();
    let peak = 0;
    const task = async () => {
      peak = Math.max(peak, l.active);
      await g.p;
    };
    const running = [l.run(task), l.run(task), l.run(task)];
    await Promise.resolve();
    expect(l.active).toBe(2);
    expect(l.queued).toBe(1);
    await expect(l.run(task)).rejects.toBeInstanceOf(LimitExceededError);
    g.open();
    await Promise.all(running);
    expect(peak).toBeLessThanOrEqual(2);
    expect(l.active).toBe(0);
    expect(l.queued).toBe(0);
  });

  it('frees the slot when a task throws', async () => {
    const l = new ConcurrencyLimiter(1, 0);
    await expect(
      l.run(async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(await l.run(async () => 'ok')).toBe('ok');
  });
});

describe('RATE_LIMITS', () => {
  it('bounds Argon2id memory: concurrency x 19 MiB stays under 100 MiB', () => {
    expect(RATE_LIMITS.PASSWORD_VERIFY_CONCURRENCY * 19).toBeLessThan(100);
  });
});
