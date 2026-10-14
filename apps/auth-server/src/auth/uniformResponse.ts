// [JDH] Dummy Argon2id verify for unknown users, fixed minimum duration, byte-identical errors
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { toPublicErrorCode } from '@deltaforce/protocol';
import { PasswordHashFormatError, hashPassword, verifyAndUpgrade } from './password.js';

/**
 * Every password-checking response takes at least this long, success or failure.
 * Our own value, not from the shared context: well above one Argon2id verify at
 * m=19456 t=2 p=1 (about 24 ms, docs/benchmarks/argon2id.md) so the floor, not the
 * work, sets the response time. Team can change it.
 */
export const MIN_AUTH_RESPONSE_MS = 250;

export interface AuthResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  /** Exact bytes to send. Identical for every kind of failure. */
  readonly body: string;
}

/** The one failure response: unknown user, wrong password and broken stored hash all look like this. */
export const AUTH_FAILURE: AuthResponse = Object.freeze({
  status: 401,
  headers: Object.freeze({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  }),
  body: JSON.stringify({ code: toPublicErrorCode('AUTH_FAILED') }),
});

// A real Argon2id hash at the current parameters, of a random value nobody knows. Verifying
// against it costs exactly what verifying a real user's hash costs.
let dummyHash: Promise<string> | undefined;
export function dummyPasswordHash(): Promise<string> {
  dummyHash ??= hashPassword(randomBytes(32).toString('base64url'));
  return dummyHash;
}

/** Compute the dummy hash at boot so the first unknown-user login is not the slow one. */
export async function warmUp(): Promise<void> {
  await dummyPasswordHash();
}

/** Runs `work` and resolves (or rejects) no sooner than `minMs` after it started. */
export async function withMinimumDuration<T>(
  work: () => Promise<T>,
  minMs = MIN_AUTH_RESPONSE_MS,
): Promise<T> {
  const started = performance.now();
  const settle = async () => {
    // Timers can fire a fraction of a millisecond early, so re-check instead of trusting one sleep.
    for (let left = minMs - (performance.now() - started); left > 0; ) {
      await sleep(Math.ceil(left));
      left = minMs - (performance.now() - started);
    }
  };
  try {
    const result = await work();
    await settle();
    return result;
  } catch (err) {
    await settle();
    throw err;
  }
}

export interface PasswordCheckDeps {
  /** The stored Argon2id hash for this user, or null when there is no such user or no password. */
  findPasswordHash(username: string): Promise<string | null>;
  /** Called by rehash-on-login with a hash at current parameters. */
  savePasswordHash(username: string, hash: string): Promise<void>;
  minResponseMs?: number;
}

export type PasswordCheck = { ok: true } | { ok: false; response: AuthResponse };

/**
 * Checks a password so that an unknown user and a wrong password are indistinguishable:
 * the same Argon2id work runs either way, the call takes at least `MIN_AUTH_RESPONSE_MS`,
 * and every failure returns the byte-identical `AUTH_FAILURE`.
 */
export function checkPasswordUniformly(
  deps: PasswordCheckDeps,
  username: string,
  password: string,
): Promise<PasswordCheck> {
  return withMinimumDuration(async () => {
    // Both lookups run on every call, so a known and an unknown user reach Argon2id on the
    // same tick. An extra await on one path alone makes its jobs queue behind the other's
    // when the thread pool is busy, and that ordering is measurable under load.
    const [stored, dummy] = await Promise.all([
      deps.findPasswordHash(username),
      dummyPasswordHash(),
    ]);
    const hash = stored ?? dummy;
    let verified: boolean;
    try {
      verified = await verifyAndUpgrade(password, hash, (h) => deps.savePasswordHash(username, h));
    } catch (err) {
      // A corrupted stored hash must not answer differently from a wrong password.
      if (err instanceof PasswordHashFormatError) verified = false;
      else throw err;
    }
    return stored !== null && verified ? { ok: true } : { ok: false, response: AUTH_FAILURE };
  }, deps.minResponseMs);
}
