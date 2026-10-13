// [RMR] Breached password rejected; 40-character passphrase with spaces accepted
import { createHash } from 'node:crypto';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BreachListFormatError,
  POLICY_MESSAGES,
  PASSWORD_POLICY,
  checkPassword,
  loadLocalBreachList,
  type BreachedRangeSource,
  type PolicyFailureReason,
} from './passwordPolicy.js';

const sha1 = (s: string) => createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
const noBreaches: BreachedRangeSource = { range: async () => new Set() };

afterEach(() => vi.restoreAllMocks());

describe('acceptance', () => {
  it('rejects a known breached password with a plain explanation', async () => {
    const result = await checkPassword('password1234');
    expect(result).toMatchObject({ ok: false, reason: 'BREACHED' });
    if (result.ok) return;
    expect(result.message).toContain('choose a different one');
    expect(result.message).not.toMatch(/[<>]/);
    expect(result.message).not.toContain('password1234');
  });

  it('accepts a 40-character passphrase containing spaces', async () => {
    const passphrase = 'quiet river carries seven purple lantern';
    expect([...passphrase].length).toBe(40);
    expect(passphrase).toContain(' ');
    expect(await checkPassword(passphrase)).toEqual({ ok: true });
  });
});

describe('length', () => {
  const of = (n: number, ch = 'x') => ch.repeat(n);

  it.each([
    [7, 'TOO_SHORT'],
    [1025, 'TOO_LONG'],
  ] as const)('rejects %i characters', async (n, reason) => {
    expect(await checkPassword(of(n), { breached: noBreaches })).toMatchObject({ reason });
  });

  it.each([8, 64, 1024])('accepts %i characters', async (n) => {
    expect(await checkPassword(of(n), { breached: noBreaches })).toEqual({ ok: true });
  });

  it('counts code points, not UTF-16 units', async () => {
    expect(await checkPassword('🔑'.repeat(8), { breached: noBreaches })).toEqual({ ok: true });
    expect(await checkPassword('🔑'.repeat(7), { breached: noBreaches })).toMatchObject({
      reason: 'TOO_SHORT',
    });
  });

  it('does not normalise an enormous input before rejecting it', async () => {
    const spy = vi.spyOn(String.prototype, 'normalize');
    expect(await checkPassword('x'.repeat(1024 * 8 + 1), { breached: noBreaches })).toMatchObject({
      reason: 'TOO_LONG',
    });
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('no composition rules', () => {
  it.each([
    ['only lowercase', 'qzjxkvwmpt'],
    ['only digits', '48151623'],
    ['only spaces inside', 'a    b    c'],
    ['Sinhala', 'සුරක්ෂිත මුරපදයක් වේ'],
    ['Tamil', 'பாதுகாப்பான கடவுச்சொல்'],
    ['CJK', '这是一个很长的密码短语'],
  ])('accepts %s', async (_name, password) => {
    expect(await checkPassword(password, { breached: noBreaches })).toEqual({ ok: true });
  });

  it('records that there is no rotation or composition rule', () => {
    expect(PASSWORD_POLICY).toMatchObject({
      minChars: 8,
      maxChars: 1024,
      compositionRules: 'none',
      rotation: 'never',
    });
    expect(Object.keys(PASSWORD_POLICY).some((k) => /expir|age|rotat.*days/i.test(k))).toBe(false);
  });
});

describe('malformed input', () => {
  it.each([
    ['lone high surrogate', 'abcdefg\uD800h'],
    ['lone low surrogate', 'abcdefg\uDC00h'],
  ])('rejects a %s', async (_name, password) => {
    expect(await checkPassword(password, { breached: noBreaches })).toMatchObject({
      reason: 'MALFORMED',
    });
  });

  it.each([undefined, null, 12345678, {}, ['a']])('rejects a non-string %j', async (value) => {
    expect(await checkPassword(value, { breached: noBreaches })).toMatchObject({
      reason: 'MALFORMED',
    });
  });
});

describe('context words', () => {
  const context = { userId: 'Alice.Example@mail.test' };

  it.each(['alice.example@mail.test', 'ALICE.EXAMPLE', 'DeltaForce', 'auth.deltaforce.lk'])(
    'rejects %s',
    async (password) => {
      expect(await checkPassword(password, { breached: noBreaches, context })).toMatchObject({
        reason: 'CONTEXT_WORD',
      });
    },
  );

  it('only matches the whole password, so a longer passphrase is fine', async () => {
    expect(
      await checkPassword('alice.example likes deltaforce', { breached: noBreaches, context }),
    ).toEqual({ ok: true });
  });
});

describe('k-anonymity', () => {
  it('only ever hands the source a 5-character hash prefix', async () => {
    const prefixes: string[] = [];
    const spy: BreachedRangeSource = {
      range: async (p) => {
        prefixes.push(p);
        return new Set();
      },
    };
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const password = 'quiet river carries seven purple lantern';

    await checkPassword(password, { breached: spy });

    expect(prefixes.length).toBeGreaterThan(0);
    for (const p of prefixes) {
      expect(p).toMatch(/^[0-9A-F]{5}$/);
      expect(password).not.toContain(p);
    }
    expect(prefixes).toContain(sha1(password).slice(0, 5));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('compares the suffix locally', async () => {
    const password = 'a very private passphrase';
    const hash = sha1(password);
    const source: BreachedRangeSource = {
      range: async (p) => (p === hash.slice(0, 5) ? new Set([hash.slice(5)]) : new Set()),
    };
    expect(await checkPassword(password, { breached: source })).toMatchObject({
      reason: 'BREACHED',
    });
  });

  it('catches a breached entry typed in a compatibility form (fullwidth)', async () => {
    // NFKC folds fullwidth letters and digits to plain ASCII
    expect(await checkPassword('ｐａｓｓｗｏｒｄ１２３４')).toMatchObject({ reason: 'BREACHED' });
  });
});

describe('messages', () => {
  it('never contain the password, whatever the reason', async () => {
    const password = 'Zx9-unlikely-secret';
    for (const message of Object.values(POLICY_MESSAGES)) {
      expect(message).not.toContain(password);
      expect(message).not.toMatch(/[<>]/);
    }
    const reasons: PolicyFailureReason[] = [
      'MALFORMED',
      'TOO_SHORT',
      'TOO_LONG',
      'CONTEXT_WORD',
      'BREACHED',
    ];
    expect(Object.keys(POLICY_MESSAGES).sort()).toEqual([...reasons].sort());
  });
});

describe('loadLocalBreachList', () => {
  const write = (body: string) => {
    const path = join(mkdtempSync(join(tmpdir(), 'breach-')), 'list.txt');
    writeFileSync(path, body);
    return path;
  };

  it('accepts SHA1 and SHA1:COUNT lines', async () => {
    const a = sha1('first entry');
    const b = sha1('second entry');
    const list = await loadLocalBreachList(write(`${a}\n${b}:42\n`));
    expect((await list.range(a.slice(0, 5))).has(a.slice(5))).toBe(true);
    expect((await list.range(b.slice(0, 5))).has(b.slice(5))).toBe(true);
    expect((await list.range('00000')).size).toBe(0);
  });

  it('fails at load time on a malformed line, without echoing it', async () => {
    const err = await loadLocalBreachList(write(`${sha1('ok')}\nnot-a-hash-secret\n`)).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(BreachListFormatError);
    expect((err as Error).message).not.toContain('not-a-hash-secret');
    expect((err as Error).message).toContain('line 2');
  });
});
