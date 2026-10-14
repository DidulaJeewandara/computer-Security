// [JDH] Every rate limit in the system, declared in this one file
//
// The shared context fixes only the 5 shared verify attempts per pending record and the
// 10 minute pending-auth TTL (packages/protocol constants). Every other number below is
// our own choice, picked for a two-day demo on one server; the team can change any of them
// here without touching a route handler.

export interface BucketLimit {
  /** Requests allowed in a burst. */
  readonly capacity: number;
  /** Sustained rate once the burst is spent. */
  readonly refillPerSecond: number;
}

export const RATE_LIMITS = Object.freeze({
  /** Hellos per client IP. Every hello costs the server an HPKE seal and a pending record. */
  HELLO_PER_IP: Object.freeze({ capacity: 10, refillPerSecond: 0.5 }) satisfies BucketLimit,
  /** Pending records one identity may hold at once; a new hello evicts that identity's oldest. */
  PENDING_PER_IDENTITY: 3,
  /** Pending records across all identities; beyond this, new hellos are refused. */
  PENDING_TOTAL: 10_000,
  /** Argon2id verifies running at once. Each one holds 19 MiB, so this bounds memory at ~76 MiB. */
  PASSWORD_VERIFY_CONCURRENCY: 4,
  /** Password checks allowed to wait for a free slot; beyond this they are refused, not queued. */
  PASSWORD_VERIFY_QUEUE: 64,
  /** OTP sends per identity and channel: a few "call me again" / "replay" requests, then one a minute. */
  OTP_SEND_PER_CHANNEL: Object.freeze({
    capacity: 3,
    refillPerSecond: 1 / 60,
  }) satisfies BucketLimit,
  /**
   * OTP verifies per identity, across pending records, so starting a new login does not buy a
   * fresh set of guesses. Two logins' worth of the 5 shared attempts, then one a minute.
   */
  OTP_VERIFY_PER_IDENTITY: Object.freeze({
    capacity: 10,
    refillPerSecond: 1 / 60,
  }) satisfies BucketLimit,
  /** OTP verifies per client IP, across every identity it tries. */
  OTP_VERIFY_PER_IP: Object.freeze({ capacity: 20, refillPerSecond: 0.2 }) satisfies BucketLimit,
  /** Distinct keys (IPs, identities) a limiter remembers; the least recently seen is forgotten first. */
  TRACKED_KEYS_MAX: 50_000,
});

export type Clock = () => number;

export type TakeResult = { ok: true } | { ok: false; retryAfterMs: number };

/**
 * Token bucket per key, with a hard cap on how many keys it remembers, so a flood of
 * distinct keys cannot grow it without limit.
 */
export class TokenBucketLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();

  constructor(
    private readonly limit: BucketLimit,
    private readonly opts: { maxKeys?: number; now?: Clock } = {},
  ) {}

  private get now(): number {
    return (this.opts.now ?? Date.now)();
  }

  take(key: string, cost = 1): TakeResult {
    const now = this.now;
    const prev = this.buckets.get(key);
    const tokens = prev
      ? Math.min(
          this.limit.capacity,
          prev.tokens + ((now - prev.at) / 1000) * this.limit.refillPerSecond,
        )
      : this.limit.capacity;
    // Re-insert so Map order is least recently seen first.
    this.buckets.delete(key);
    if (tokens < cost) {
      this.buckets.set(key, { tokens, at: now });
      this.trim();
      const retryAfterMs = Math.ceil(((cost - tokens) / this.limit.refillPerSecond) * 1000);
      return { ok: false, retryAfterMs };
    }
    this.buckets.set(key, { tokens: tokens - cost, at: now });
    this.trim();
    return { ok: true };
  }

  get size(): number {
    return this.buckets.size;
  }

  private trim(): void {
    const max = this.opts.maxKeys ?? RATE_LIMITS.TRACKED_KEYS_MAX;
    while (this.buckets.size > max) {
      const oldest = this.buckets.keys().next().value as string;
      this.buckets.delete(oldest);
    }
  }
}

export class LimitExceededError extends Error {
  constructor() {
    super('RATE_LIMITED');
    this.name = 'LimitExceededError';
  }
}

/** Runs at most `concurrency` tasks at once and lets at most `queue` wait; the rest are refused. */
export class ConcurrencyLimiter {
  private running = 0;
  private readonly waiting: (() => void)[] = [];

  constructor(
    private readonly concurrency: number,
    private readonly queue: number,
  ) {}

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.running >= this.concurrency) {
      if (this.waiting.length >= this.queue) throw new LimitExceededError();
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.running++;
    }
    try {
      return await task();
    } finally {
      const next = this.waiting.shift();
      // Hand the slot straight to the next waiter, so `running` never dips and lets a newcomer jump the queue.
      if (next) next();
      else this.running--;
    }
  }

  get active(): number {
    return this.running;
  }

  get queued(): number {
    return this.waiting.length;
  }
}
