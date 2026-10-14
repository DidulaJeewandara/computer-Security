// [JDH] Used, expired, cross-handshake, cross-user, brute force, log redaction (T2, T5)
import { InMemoryAttemptStore, OtpAbuseGuard, RATE_LIMITS } from '@deltaforce/policy';
import { NOTATION } from '@deltaforce/protocol';
import { describe, expect, it } from 'vitest';

describe('brute force is bounded by the rate limit', () => {
  /**
   * An attacker who knows the password, starting a fresh pending record whenever the 5 shared
   * attempts run out, guessing from as many IPs as they like. Only the per-identity verify
   * bucket stands in the way, so it alone sets the bound.
   */
  async function guessesAllowedIn(ms: number): Promise<number> {
    let t = 0;
    const guard = new OtpAbuseGuard({ attempts: new InMemoryAttemptStore(), now: () => t });
    let allowed = 0;
    let pending = 0;
    let ipCounter = 0;
    let failuresHere = 0;
    for (; t <= ms; t += 1000) {
      // try as fast as the guard allows: up to 100 guesses a second
      for (let k = 0; k < 100; k++) {
        if (failuresHere === NOTATION.PENDING_AUTH.MAX_VERIFY_ATTEMPTS) {
          pending++;
          failuresHere = 0;
        }
        const check = await guard.beforeVerify(
          `p${pending}`,
          'alice',
          `10.0.${ipCounter >> 8}.${ipCounter++ & 255}`,
        );
        if (!check.ok) break;
        allowed++;
        await guard.afterFailure(`p${pending}`);
        failuresHere++;
      }
    }
    return allowed;
  }

  it('allows at most burst + one guess a minute against one account', async () => {
    const day = 24 * 60 * 60 * 1000;
    const allowed = await guessesAllowedIn(day);
    const L = RATE_LIMITS.OTP_VERIFY_PER_IDENTITY;
    expect(allowed).toBeLessThanOrEqual(L.capacity + Math.ceil((day / 1000) * L.refillPerSecond));
  }, 60_000);

  it('keeps the chance of guessing a code in a day under 1 in 500', async () => {
    const allowed = await guessesAllowedIn(24 * 60 * 60 * 1000);
    const space = 10 ** NOTATION.OTP.DIGITS;
    // Each pending record has its own code, so each guess is an independent 1-in-10^6 try.
    const pDay = 1 - (1 - 1 / space) ** allowed;
    expect(pDay).toBeLessThan(1 / 500);
  }, 60_000);
});

// The cases below need the OTP core and steps 4/5b (P4-RMR-1, P4-RMR-2), which are not on
// main yet. They are listed here so CI reports them as todo rather than missing.
describe('OTP attacks against the OTP service', () => {
  it.todo('a used code is rejected');
  it.todo('an expired code is rejected');
  it.todo('a code from another handshake is rejected');
  it.todo("user A's code is rejected for user B");
  it.todo('no code ever reaches a log line or an error object');
});
