// [JDH] P2-JDH-2: a hello flood cannot exhaust memory, and legitimate logins still succeed during it
import { LimitExceededError } from '@deltaforce/policy';
import { describe, expect, it } from 'vitest';
import { hashPassword } from '../auth/password.js';
import { checkPasswordUniformly } from '../auth/uniformResponse.js';
import { DEFAULT_HANDSHAKE_LIMITS, HandshakeGuard } from './handshakeAbuse.js';

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe('per-IP hello limit', () => {
  it('admits a burst, then refuses with a retry delay, then admits again after refill', () => {
    const c = clock();
    const g = new HandshakeGuard({ now: c.now });
    const burst = DEFAULT_HANDSHAKE_LIMITS.helloPerIp.capacity;
    for (let i = 0; i < burst; i++) expect(g.admitHello('203.0.113.9', `user${i}`).ok).toBe(true);
    const refused = g.admitHello('203.0.113.9', 'another');
    expect(refused).toMatchObject({ ok: false, code: 'RATE_LIMITED' });
    if (refused.ok) throw new Error('unreachable');
    expect(refused.retryAfterMs).toBeGreaterThan(0);
    c.advance(refused.retryAfterMs);
    expect(g.admitHello('203.0.113.9', 'another').ok).toBe(true);
  });

  it('does not slow down a different IP', () => {
    const g = new HandshakeGuard({ now: () => 0 });
    for (let i = 0; i < 50; i++) g.admitHello('203.0.113.9', `u${i}`);
    expect(g.admitHello('198.51.100.7', 'alice').ok).toBe(true);
  });
});

describe('pending records per identity', () => {
  it('caps them, evicting the oldest so a new hello always gets in', () => {
    const g = new HandshakeGuard({ now: () => 0 });
    const cap = DEFAULT_HANDSHAKE_LIMITS.pendingPerIdentity;
    const tickets = Array.from({ length: cap }, (_, i) => {
      const r = g.admitHello(`192.0.2.${i}`, 'alice');
      if (!r.ok) throw new Error('should admit');
      return r.ticket;
    });
    const next = g.admitHello('192.0.2.200', 'alice');
    expect(next).toMatchObject({ ok: true, evicted: tickets[0] });
    expect(g.stats().pending).toBe(cap);
  });

  it('frees capacity on release and on expiry after the pending-auth TTL', () => {
    const c = clock();
    const g = new HandshakeGuard({ now: c.now, limits: { pendingTotal: 2 } });
    const a = g.admitHello('192.0.2.1', 'a');
    g.admitHello('192.0.2.2', 'b');
    expect(g.admitHello('192.0.2.3', 'c').ok).toBe(false);
    if (!a.ok) throw new Error('should admit');
    g.release(a.ticket);
    expect(g.admitHello('192.0.2.3', 'c').ok).toBe(true);
    expect(g.admitHello('192.0.2.4', 'd').ok).toBe(false);
    c.advance(DEFAULT_HANDSHAKE_LIMITS.pendingTtlMs);
    expect(g.admitHello('192.0.2.4', 'd').ok).toBe(true);
    expect(g.stats().pending).toBe(1);
  });
});

describe('total pending records', () => {
  it('refuses new identities at the cap instead of evicting logins in progress', () => {
    const g = new HandshakeGuard({ now: () => 0, limits: { pendingTotal: 5 } });
    const first = g.admitHello('192.0.2.1', 'slow-screen-reader-user');
    for (let i = 0; i < 4; i++) g.admitHello(`192.0.2.${10 + i}`, `u${i}`);
    expect(g.admitHello('192.0.2.99', 'newcomer')).toMatchObject({
      ok: false,
      code: 'RATE_LIMITED',
    });
    if (!first.ok) throw new Error('should admit');
    // the in-progress login was not evicted
    expect(g.stats().pending).toBe(5);
    g.release(first.ticket);
    expect(g.stats().pending).toBe(4);
  });

  it('still lets an identity at its own cap replace its oldest record when the total is full', () => {
    const g = new HandshakeGuard({
      now: () => 0,
      limits: { pendingTotal: 3, pendingPerIdentity: 3 },
    });
    for (let i = 0; i < 3; i++) g.admitHello(`192.0.2.${i}`, 'alice');
    expect(g.admitHello('192.0.2.50', 'alice')).toMatchObject({ ok: true });
    expect(g.stats().pending).toBe(3);
  });
});

describe('flood', () => {
  it('cannot exhaust memory, and a legitimate login still succeeds while it is happening', async () => {
    const c = clock();
    const g = new HandshakeGuard({ now: c.now });
    const L = DEFAULT_HANDSHAKE_LIMITS;
    const heapBefore = process.memoryUsage().heapUsed;

    // 300k hellos over five simulated minutes: a few noisy IPs, a long tail of distinct
    // IPs, and a stream aimed at the victim's username.
    let refused = 0;
    for (let i = 0; i < 300_000; i++) {
      if (i % 1000 === 0) c.advance(1000);
      const ip =
        i % 3 === 0 ? `203.0.113.${i % 7}` : `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
      const identity = i % 5 === 0 ? 'alice' : `bot-${i}`;
      if (!g.admitHello(ip, identity).ok) refused++;
      const s = g.stats();
      if (s.pending > L.pendingTotal || s.trackedIps > L.trackedKeysMax) {
        throw new Error(`bound exceeded at ${i}: ${JSON.stringify(s)}`);
      }
    }
    const s = g.stats();
    expect(refused).toBeGreaterThan(0);
    expect(s.pending).toBeLessThanOrEqual(L.pendingTotal);
    expect(s.trackedIps).toBeLessThanOrEqual(L.trackedKeysMax);
    // Generous: bounded structures hold well under 64 MiB however long the flood runs.
    expect(process.memoryUsage().heapUsed - heapBefore).toBeLessThan(64 * 1024 * 1024);

    // Alice, from her own IP, mid-flood: her hello gets in even though the attacker is
    // sending hellos for her username...
    const hello = g.admitHello('198.51.100.20', 'alice');
    expect(hello.ok).toBe(true);
    // ...and her password check runs under the Argon2id bound and succeeds.
    const aliceHash = await hashPassword('correct horse battery staple');
    const result = await g.runPasswordWork(() =>
      checkPasswordUniformly(
        {
          findPasswordHash: async (u) => (u === 'alice' ? aliceHash : null),
          savePasswordHash: async () => {},
        },
        'alice',
        'correct horse battery staple',
      ),
    );
    expect(result).toEqual({ ok: true });
  }, 60_000);

  it('when a distributed flood fills the total, newcomers get a graceful RATE_LIMITED with a retry time', () => {
    // Documented trade-off (handshakeAbuse.ts): at the total cap we refuse rather than evict,
    // so logins already in progress survive. Filling the cap at all takes at least
    // pendingTotal / helloPerIp.capacity distinct IPs, because each IP only gets a burst.
    const L = DEFAULT_HANDSHAKE_LIMITS;
    expect(L.pendingTotal / L.helloPerIp.capacity).toBeGreaterThanOrEqual(1000);
    const c = clock();
    const g = new HandshakeGuard({ now: c.now, limits: { pendingTotal: 10 } });
    for (let i = 0; i < 10; i++) g.admitHello(`10.0.0.${i}`, `bot-${i}`);
    const refused = g.admitHello('198.51.100.20', 'alice');
    expect(refused).toMatchObject({ ok: false, code: 'RATE_LIMITED' });
    if (refused.ok) throw new Error('unreachable');
    expect(refused.retryAfterMs).toBe(L.pendingTtlMs);
    c.advance(refused.retryAfterMs);
    expect(g.admitHello('198.51.100.20', 'alice').ok).toBe(true);
  });
});

describe('password work bound', () => {
  it('never runs more Argon2id verifies at once than the bound, and refuses past the queue', async () => {
    const g = new HandshakeGuard({
      limits: { passwordVerifyConcurrency: 2, passwordVerifyQueue: 3 },
    });
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let peak = 0;
    const work = () =>
      g.runPasswordWork(async () => {
        peak = Math.max(peak, g.stats().passwordActive);
        await held;
      });
    const accepted = Array.from({ length: 5 }, work);
    await Promise.resolve();
    await expect(work()).rejects.toBeInstanceOf(LimitExceededError);
    release();
    await Promise.all(accepted);
    expect(peak).toBe(2);
  });
});
