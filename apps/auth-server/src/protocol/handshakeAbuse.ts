// [JDH] Per-IP hello rate limit, cap on pending records per identity, bounded memory
//
// The hello handler calls admitHello() BEFORE any HPKE work or pending-record write, and
// release() whenever a pending record completes, fails or is deleted. Password checks run
// inside runPasswordWork() so a flood cannot hold more than a fixed number of 19 MiB
// Argon2id verifies in memory at once.
import { randomBytes } from 'node:crypto';
import { NOTATION } from '@deltaforce/protocol';
import {
  ConcurrencyLimiter,
  RATE_LIMITS,
  TokenBucketLimiter,
  type BucketLimit,
  type Clock,
} from '@deltaforce/policy';

export interface HandshakeLimits {
  helloPerIp: BucketLimit;
  pendingPerIdentity: number;
  pendingTotal: number;
  passwordVerifyConcurrency: number;
  passwordVerifyQueue: number;
  trackedKeysMax: number;
  pendingTtlMs: number;
}

export const DEFAULT_HANDSHAKE_LIMITS: Readonly<HandshakeLimits> = Object.freeze({
  helloPerIp: RATE_LIMITS.HELLO_PER_IP,
  pendingPerIdentity: RATE_LIMITS.PENDING_PER_IDENTITY,
  pendingTotal: RATE_LIMITS.PENDING_TOTAL,
  passwordVerifyConcurrency: RATE_LIMITS.PASSWORD_VERIFY_CONCURRENCY,
  passwordVerifyQueue: RATE_LIMITS.PASSWORD_VERIFY_QUEUE,
  trackedKeysMax: RATE_LIMITS.TRACKED_KEYS_MAX,
  pendingTtlMs: NOTATION.PENDING_AUTH.TTL_SECONDS * 1000,
});

export type HelloAdmission =
  | {
      ok: true;
      /** Opaque handle for this pending record; pass it to release(). */
      ticket: string;
      /** A ticket of the same identity that was evicted to make room; delete its pending record. */
      evicted?: string;
    }
  | { ok: false; code: 'RATE_LIMITED'; retryAfterMs: number };

export class HandshakeGuard {
  private readonly limits: HandshakeLimits;
  private readonly now: Clock;
  private readonly helloBuckets: TokenBucketLimiter;
  private readonly passwordWork: ConcurrencyLimiter;
  /** Insertion order is admission order, so expired tickets are always at the front. */
  private readonly tickets = new Map<string, { identity: string; at: number }>();
  private readonly byIdentity = new Map<string, string[]>();

  constructor(opts: { limits?: Partial<HandshakeLimits>; now?: Clock } = {}) {
    this.limits = { ...DEFAULT_HANDSHAKE_LIMITS, ...opts.limits };
    this.now = opts.now ?? Date.now;
    this.helloBuckets = new TokenBucketLimiter(this.limits.helloPerIp, {
      maxKeys: this.limits.trackedKeysMax,
      now: this.now,
    });
    this.passwordWork = new ConcurrencyLimiter(
      this.limits.passwordVerifyConcurrency,
      this.limits.passwordVerifyQueue,
    );
  }

  admitHello(ip: string, identity: string): HelloAdmission {
    this.expire();

    const bucket = this.helloBuckets.take(ip);
    if (!bucket.ok) return { ok: false, code: 'RATE_LIMITED', retryAfterMs: bucket.retryAfterMs };

    // Per identity: a new hello always gets in and the oldest is evicted. Refusing instead
    // would let anyone who knows a username stop that user from starting a login at all.
    const mine = this.byIdentity.get(identity) ?? [];
    const evicted = mine.length >= this.limits.pendingPerIdentity ? mine[0] : undefined;

    // Across everyone: refuse rather than evict, so a distributed flood cannot kill logins
    // already in progress, which for a screen-reader user can take minutes. An admission
    // that evicts one of its own identity's records does not grow the total, so it passes.
    if (!evicted && this.tickets.size >= this.limits.pendingTotal) {
      return { ok: false, code: 'RATE_LIMITED', retryAfterMs: this.oldestExpiresInMs() };
    }
    if (evicted) this.release(evicted);

    const ticket = randomBytes(16).toString('base64url');
    this.tickets.set(ticket, { identity, at: this.now() });
    const list = this.byIdentity.get(identity) ?? [];
    list.push(ticket);
    this.byIdentity.set(identity, list);
    return evicted ? { ok: true, ticket, evicted } : { ok: true, ticket };
  }

  /** The pending record behind this ticket is gone (completed, failed, expired or deleted). */
  release(ticket: string): void {
    const t = this.tickets.get(ticket);
    if (!t) return;
    this.tickets.delete(ticket);
    const list = this.byIdentity.get(t.identity);
    if (!list) return;
    const rest = list.filter((x) => x !== ticket);
    if (rest.length === 0) this.byIdentity.delete(t.identity);
    else this.byIdentity.set(t.identity, rest);
  }

  /** Run one password check under the Argon2id concurrency bound. Throws LimitExceededError when full. */
  runPasswordWork<T>(task: () => Promise<T>): Promise<T> {
    return this.passwordWork.run(task);
  }

  stats(): {
    pending: number;
    identities: number;
    trackedIps: number;
    passwordActive: number;
    passwordQueued: number;
  } {
    return {
      pending: this.tickets.size,
      identities: this.byIdentity.size,
      trackedIps: this.helloBuckets.size,
      passwordActive: this.passwordWork.active,
      passwordQueued: this.passwordWork.queued,
    };
  }

  private expire(): void {
    const cutoff = this.now() - this.limits.pendingTtlMs;
    for (const [ticket, t] of this.tickets) {
      if (t.at > cutoff) break;
      this.release(ticket);
    }
  }

  private oldestExpiresInMs(): number {
    const first = this.tickets.values().next().value;
    return first ? Math.max(0, first.at + this.limits.pendingTtlMs - this.now()) : 0;
  }
}
