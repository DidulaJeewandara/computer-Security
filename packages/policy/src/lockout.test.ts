// [JDH] Switching channel does not reset the counter
import { describe, expect, it } from 'vitest';
import {
  InMemoryAttemptStore,
  LOCKOUT_MESSAGES,
  MAX_VERIFY_ATTEMPTS,
  OtpAbuseGuard,
  type OtpCheck,
} from './lockout.js';
import { RATE_LIMITS } from './rateLimits.js';

function setup() {
  let t = 0;
  const clock = { now: () => t, advance: (ms: number) => (t += ms) };
  const guard = new OtpAbuseGuard({ attempts: new InMemoryAttemptStore(), now: clock.now });
  return { guard, clock };
}

/** A wrong code submitted through whichever channel delivered it. */
async function wrongCode(guard: OtpAbuseGuard, pendingId: string, ip = '198.51.100.1') {
  const check = await guard.beforeVerify(pendingId, 'alice', ip);
  if (!check.ok) return check;
  return guard.afterFailure(pendingId);
}

describe('shared attempt counter', () => {
  it('keeps counting when the user switches channel', async () => {
    const { guard } = setup();
    const results = [];
    // voice, voice, haptic, voice, haptic: one pending record throughout
    for (const channel of ['voice', 'voice', 'haptic', 'voice', 'haptic']) {
      expect(guard.beforeSend('alice', channel).ok).toBe(true);
      results.push(await wrongCode(guard, 'pending-1'));
    }
    expect(results.map((r) => ('remaining' in r ? r.remaining : null))).toEqual([4, 3, 2, 1, 0]);
    const sixth = await guard.beforeVerify('pending-1', 'alice', '198.51.100.1');
    expect(sixth).toMatchObject({ ok: false, reason: 'ATTEMPTS_EXHAUSTED' });
  });

  it(`stops the pending record after exactly ${MAX_VERIFY_ATTEMPTS} failures`, async () => {
    const { guard } = setup();
    for (let i = 1; i < MAX_VERIFY_ATTEMPTS; i++) {
      expect(await wrongCode(guard, 'p')).toMatchObject({ exhausted: false });
    }
    expect(await wrongCode(guard, 'p')).toMatchObject({ exhausted: true, remaining: 0 });
  });

  it('a different pending record has its own count', async () => {
    const { guard } = setup();
    for (let i = 0; i < MAX_VERIFY_ATTEMPTS; i++) await wrongCode(guard, 'p1');
    expect((await guard.beforeVerify('p2', 'alice', '198.51.100.1')).ok).toBe(true);
  });
});

describe('verify rate limits', () => {
  it('per identity: starting new logins does not buy unlimited guesses', async () => {
    const { guard } = setup();
    const cap = RATE_LIMITS.OTP_VERIFY_PER_IDENTITY.capacity;
    let allowed = 0;
    let last: OtpCheck = { ok: true };
    // A fresh pending record every 5 guesses, from a fresh IP each time.
    for (let i = 0; i < 100 && last.ok; i++) {
      const pendingId = `pending-${Math.floor(i / 5)}`;
      last = await guard.beforeVerify(pendingId, 'alice', `10.0.0.${i}`);
      if (last.ok) {
        allowed++;
        await guard.afterFailure(pendingId);
      }
    }
    expect(allowed).toBe(cap);
    expect(last).toMatchObject({ ok: false, reason: 'RATE_LIMITED' });
  });

  it('per IP: one address cannot spray guesses across many accounts', async () => {
    const { guard } = setup();
    const cap = RATE_LIMITS.OTP_VERIFY_PER_IP.capacity;
    const results = [];
    for (let i = 0; i <= cap; i++) {
      results.push(await guard.beforeVerify(`p${i}`, `user${i}`, '203.0.113.5'));
    }
    expect(results.filter((r) => r.ok)).toHaveLength(cap);
    expect(results.at(-1)).toMatchObject({ ok: false, reason: 'RATE_LIMITED' });
  });

  it('recovers with time', async () => {
    const { guard, clock } = setup();
    for (let i = 0; i < RATE_LIMITS.OTP_VERIFY_PER_IP.capacity; i++) {
      await guard.beforeVerify(`p${i}`, `user${i}`, '203.0.113.5');
    }
    const refused = await guard.beforeVerify('px', 'userx', '203.0.113.5');
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error('unreachable');
    clock.advance(refused.retryAfterMs!);
    expect((await guard.beforeVerify('px', 'userx', '203.0.113.5')).ok).toBe(true);
  });
});

describe('send rate limit', () => {
  it('allows a few re-sends per channel, then pauses with a retry time', () => {
    const { guard } = setup();
    const cap = RATE_LIMITS.OTP_SEND_PER_CHANNEL.capacity;
    for (let i = 0; i < cap; i++) expect(guard.beforeSend('alice', 'voice').ok).toBe(true);
    expect(guard.beforeSend('alice', 'voice')).toMatchObject({ ok: false, reason: 'RATE_LIMITED' });
    // sending is limited per channel; verifying is not split by channel at all
    expect(guard.beforeSend('alice', 'haptic').ok).toBe(true);
  });
});

describe('lockout messages', () => {
  const all = [
    LOCKOUT_MESSAGES.ATTEMPTS_EXHAUSTED,
    LOCKOUT_MESSAGES.verifyRateLimited(30_000),
    LOCKOUT_MESSAGES.verifyRateLimited(150_000),
    LOCKOUT_MESSAGES.sendRateLimited(60_000),
    LOCKOUT_MESSAGES.wrongCode(1),
    LOCKOUT_MESSAGES.wrongCode(3),
  ];

  it('tell a locked-out user how to recover', () => {
    expect(LOCKOUT_MESSAGES.ATTEMPTS_EXHAUSTED).toContain('start signing in again');
    expect(LOCKOUT_MESSAGES.ATTEMPTS_EXHAUSTED).toContain('I cannot sign in');
    expect(LOCKOUT_MESSAGES.verifyRateLimited(150_000)).toContain('about 3 minutes');
    expect(LOCKOUT_MESSAGES.verifyRateLimited(150_000)).toContain('recovery code');
  });

  it('are plain sentences with no jargon and no digits that could be a code', () => {
    for (const m of all) {
      expect(m).not.toMatch(/\d{4,}/);
      expect(m).not.toMatch(/OTP|HTTP|429|RATE_LIMITED|ATTEMPTS_EXHAUSTED|token|bucket/i);
      expect(m.trim().endsWith('.')).toBe(true);
    }
  });

  it('use the right singular and plural', () => {
    expect(LOCKOUT_MESSAGES.wrongCode(1)).toContain('1 attempt left');
    expect(LOCKOUT_MESSAGES.wrongCode(2)).toContain('2 attempts left');
  });
});
