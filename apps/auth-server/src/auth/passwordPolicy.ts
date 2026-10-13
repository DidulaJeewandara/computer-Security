// [RMR] NIST SP 800-63B: 8 to 64+ chars, any Unicode, no composition rules, local breached-password check
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { IMPLEMENTATION_LIMITS, NOTATION } from '@deltaforce/protocol';

const MIN = IMPLEMENTATION_LIMITS.PASSWORD_MIN_CHARS;
const MAX = IMPLEMENTATION_LIMITS.PASSWORD_MAX_CHARS;

/** The rules, written down once. There is no expiry field because we never force rotation. */
export const PASSWORD_POLICY = Object.freeze({
  minChars: MIN,
  maxChars: MAX,
  compositionRules: 'none',
  rotation: 'never',
} as const);

// A lone surrogate becomes U+FFFD in UTF-8, so two different passwords could collide.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** NFKC, so the same text typed on different keyboards or input methods is one password. */
export const normalizePassword = (password: string): string => password.normalize('NFKC');

export type PolicyFailureReason =
  | 'MALFORMED'
  | 'TOO_SHORT'
  | 'TOO_LONG'
  | 'CONTEXT_WORD'
  | 'BREACHED';

export type PolicyResult =
  | { ok: true }
  | { ok: false; reason: PolicyFailureReason; message: string };

// Plain sentences for a screen reader. They never repeat the password.
export const POLICY_MESSAGES: Readonly<Record<PolicyFailureReason, string>> = Object.freeze({
  MALFORMED:
    'This password contains characters that cannot be stored reliably. Please retype it or choose a different one.',
  TOO_SHORT: `This password is too short. It needs at least ${MIN} characters. Spaces count, so a short phrase works well.`,
  TOO_LONG: `This password is too long. It can have up to ${MAX} characters.`,
  CONTEXT_WORD:
    'This password is too easy to guess because it matches your username or the name of this service. Please choose a different one.',
  BREACHED:
    'This password has appeared in a known data breach, so attackers are likely to try it. Please choose a different one. A passphrase of three or four unrelated words is strong and easy to type.',
});

const fail = (reason: PolicyFailureReason): PolicyResult => ({
  ok: false,
  reason,
  message: POLICY_MESSAGES[reason],
});

/** Same shape as the Pwned Passwords range API: give a 5-char prefix, get the matching suffixes. */
export interface BreachedRangeSource {
  range(prefix5: string): Promise<ReadonlySet<string>>;
}

const HASH_LINE = /^[0-9A-F]{40}(:\d+)?$/;
export const DEFAULT_BREACH_LIST = fileURLToPath(
  new URL('../../data/breached-passwords.sha1.txt', import.meta.url),
);

export class BreachListFormatError extends Error {
  constructor(lineNumber: number) {
    super(`BREACH_LIST_FORMAT: line ${lineNumber} is not a SHA-1 hash`);
    this.name = 'BreachListFormatError';
  }
}

/** Reads a file of `SHA1` or `SHA1:COUNT` lines into a prefix map. Fails loudly on a bad line. */
export async function loadLocalBreachList(
  path: string = DEFAULT_BREACH_LIST,
): Promise<BreachedRangeSource> {
  const byPrefix = new Map<string, Set<string>>();
  const lines = (await readFile(path, 'utf8')).split('\n');
  for (const [i, raw] of lines.entries()) {
    const line = raw.replace(/\r$/, '');
    if (!line) continue;
    if (!HASH_LINE.test(line)) throw new BreachListFormatError(i + 1);
    const prefix = line.slice(0, 5);
    const suffix = line.slice(5, 40);
    let set = byPrefix.get(prefix);
    if (!set) byPrefix.set(prefix, (set = new Set()));
    set.add(suffix);
  }
  const none: ReadonlySet<string> = new Set();
  return { range: async (prefix5) => byPrefix.get(prefix5) ?? none };
}

let defaultList: Promise<BreachedRangeSource> | undefined;
const bundledBreachList = () => (defaultList ??= loadLocalBreachList());

const sha1Hex = (s: string) => createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();

/** Only the 5-char prefix goes to the source; the suffix is compared here, so the password stays put. */
async function isBreached(password: string, source: BreachedRangeSource): Promise<boolean> {
  const forms = new Set([password, normalizePassword(password)]);
  for (const form of forms) {
    const hash = sha1Hex(form);
    const suffixes = await source.range(hash.slice(0, 5));
    if (suffixes.has(hash.slice(5))) return true;
  }
  return false;
}

export interface PolicyContext {
  /** U_id of the account, so the password can't be the username or the email name. */
  userId?: string;
}

const fold = (s: string) => normalizePassword(s).toLowerCase();

function contextWords(context: PolicyContext | undefined): Set<string> {
  const words = new Set([fold('deltaforce'), fold(NOTATION.S_ID)]);
  if (context?.userId) {
    words.add(fold(context.userId));
    words.add(fold(context.userId.split('@')[0]!));
  }
  return words;
}

export interface CheckPasswordOptions {
  /** Defaults to the bundled local list. */
  breached?: BreachedRangeSource;
  context?: PolicyContext;
}

export async function checkPassword(
  candidate: unknown,
  options: CheckPasswordOptions = {},
): Promise<PolicyResult> {
  if (typeof candidate !== 'string' || LONE_SURROGATE.test(candidate)) return fail('MALFORMED');
  // NFKC can grow a string a little; this just stops us normalising something huge.
  if (candidate.length > MAX * 8) return fail('TOO_LONG');

  const normalized = normalizePassword(candidate);
  const length = [...normalized].length;
  if (length < MIN) return fail('TOO_SHORT');
  if (length > MAX) return fail('TOO_LONG');

  if (contextWords(options.context).has(normalized.toLowerCase())) return fail('CONTEXT_WORD');

  const source = options.breached ?? (await bundledBreachList());
  if (await isBreached(candidate, source)) return fail('BREACHED');
  return { ok: true };
}
