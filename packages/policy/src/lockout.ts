// [JDH] 5 verify attempts SHARED across channel switches; lockout explains itself and gives a route out
import { NOTATION } from '@deltaforce/protocol';
import { RATE_LIMITS, TokenBucketLimiter, type Clock } from './rateLimits.js';

export const MAX_VERIFY_ATTEMPTS = NOTATION.PENDING_AUTH.MAX_VERIFY_ATTEMPTS;

/**
 * Where the shared attempt counter lives. The real one is the pending-auth record (P2-UDK-1),
 * keyed by the pending record only, never by channel, so switching from voice to haptic keeps
 * counting. `InMemoryAttemptStore` is for tests and development.
 */
export interface AttemptStore {
  /** Failed second-factor attempts so far on this pending record. */
  failures(pendingId: string): Promise<number>;
  /** Records one more failure and returns the new total. Must be atomic. */
  addFailure(pendingId: string): Promise<number>;
}

export class InMemoryAttemptStore implements AttemptStore {
  private readonly counts = new Map<string, number>();
  async failures(pendingId: string): Promise<number> {
    return this.counts.get(pendingId) ?? 0;
  }
  async addFailure(pendingId: string): Promise<number> {
    const n = (this.counts.get(pendingId) ?? 0) + 1;
    this.counts.set(pendingId, n);
    return n;
  }
}

export type OtpRefusalReason = 'ATTEMPTS_EXHAUSTED' | 'RATE_LIMITED';

export interface OtpRefusal {
  ok: false;
  reason: OtpRefusalReason;
  /** One plain-language message for a screen reader: what happened, and what to do next. */
  message: string;
  /** When trying again will work, if waiting is the answer. */
  retryAfterMs?: number;
}

export type OtpCheck = { ok: true } | OtpRefusal;

function wait(ms: number): string {
  const minutes = Math.ceil(ms / 60_000);
  if (ms < 60_000) return 'less than a minute';
  return minutes === 1 ? 'about 1 minute' : `about ${minutes} minutes`;
}

// Never a dead end: every message names at least one thing the user can do now.
export const LOCKOUT_MESSAGES = Object.freeze({
  ATTEMPTS_EXHAUSTED:
    'That code was not accepted, and this sign-in has now used all ' +
    `${MAX_VERIFY_ATTEMPTS} of its attempts, so it has been stopped to protect your account. ` +
    'You can start signing in again now. If you no longer have your phone or device, ' +
    'choose "I cannot sign in" to use one of your recovery codes.',
  verifyRateLimited: (ms: number) =>
    'Too many codes have been tried for this account in a short time, so code entry is paused. ' +
    `You can try again in ${wait(ms)}. ` +
    'If you have a security key, you can use it instead now. ' +
    'If you cannot wait, choose "I cannot sign in" to use a recovery code.',
  sendRateLimited: (ms: number) =>
    'A new code was requested several times in a short time, so sending is paused. ' +
    `You can ask for another code in ${wait(ms)}. ` +
    'The last code you received still works until it expires.',
  wrongCode: (remaining: number) =>
    `That code was not accepted. You have ${remaining} ${remaining === 1 ? 'attempt' : 'attempts'} left. ` +
    'Check the code and try again, or ask for it to be sent again.',
});

export interface OtpAbuseGuardOptions {
  attempts: AttemptStore;
  now?: Clock;
}

/**
 * OTP abuse controls: token buckets on sending per identity and channel, on verifying per
 * identity and per IP, and the 5 attempts per pending record shared across channels.
 */
export class OtpAbuseGuard {
  private readonly attempts: AttemptStore;
  private readonly send: TokenBucketLimiter;
  private readonly verifyIdentity: TokenBucketLimiter;
  private readonly verifyIp: TokenBucketLimiter;

  constructor(opts: OtpAbuseGuardOptions) {
    this.attempts = opts.attempts;
    const o = { now: opts.now };
    this.send = new TokenBucketLimiter(RATE_LIMITS.OTP_SEND_PER_CHANNEL, o);
    this.verifyIdentity = new TokenBucketLimiter(RATE_LIMITS.OTP_VERIFY_PER_IDENTITY, o);
    this.verifyIp = new TokenBucketLimiter(RATE_LIMITS.OTP_VERIFY_PER_IP, o);
  }

  /** Before sending (or re-sending) a code on a channel. */
  beforeSend(identity: string, channel: string): OtpCheck {
    const r = this.send.take(`${identity}\u0000${channel}`);
    if (r.ok) return r;
    return {
      ok: false,
      reason: 'RATE_LIMITED',
      message: LOCKOUT_MESSAGES.sendRateLimited(r.retryAfterMs),
      retryAfterMs: r.retryAfterMs,
    };
  }

  /**
   * Before checking a submitted code. The channel is deliberately not a parameter: the
   * counter belongs to the pending record, whichever channel delivered the code.
   */
  async beforeVerify(pendingId: string, identity: string, ip: string): Promise<OtpCheck> {
    if ((await this.attempts.failures(pendingId)) >= MAX_VERIFY_ATTEMPTS) {
      return {
        ok: false,
        reason: 'ATTEMPTS_EXHAUSTED',
        message: LOCKOUT_MESSAGES.ATTEMPTS_EXHAUSTED,
      };
    }
    for (const r of [this.verifyIdentity.take(identity), this.verifyIp.take(ip)]) {
      if (!r.ok) {
        return {
          ok: false,
          reason: 'RATE_LIMITED',
          message: LOCKOUT_MESSAGES.verifyRateLimited(r.retryAfterMs),
          retryAfterMs: r.retryAfterMs,
        };
      }
    }
    return { ok: true };
  }

  /** After a wrong code. Returns what to tell the user; the pending record fails at the limit. */
  async afterFailure(
    pendingId: string,
  ): Promise<{ remaining: number; message: string; exhausted: boolean }> {
    const used = await this.attempts.addFailure(pendingId);
    const remaining = Math.max(0, MAX_VERIFY_ATTEMPTS - used);
    return remaining === 0
      ? { remaining, exhausted: true, message: LOCKOUT_MESSAGES.ATTEMPTS_EXHAUSTED }
      : { remaining, exhausted: false, message: LOCKOUT_MESSAGES.wrongCode(remaining) };
  }
}
