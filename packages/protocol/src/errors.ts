// [RMR] Closed set of protocol error codes
import { z } from 'zod';

export const ERROR_CODES = [
  'MALFORMED_MESSAGE',
  'UNEXPECTED_STEP',
  // step-2 checks, one code per check so tests can say which one caught an attack
  'SIGNATURE_INVALID',
  'NONCE_U_MISMATCH',
  'PK_ENC_KEY_MISMATCH',
  'SERVER_ID_MISMATCH',
  'DECRYPTION_FAILED',
  'STALE_NONCE',
  'AUTH_FAILED',
  'FACTOR_NOT_OFFERED',
  'SECOND_FACTOR_FAILED',
  'ATTEMPTS_EXHAUSTED',
  'PENDING_EXPIRED',
  'REPLAY_DETECTED',
  'RATE_LIMITED',
  'KEY_ROTATED',
  'INTERNAL',
] as const;

export const ErrorCodeSchema = z.enum(ERROR_CODES);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/**
 * What a client is allowed to see. Internal reasons that would let an attacker
 * tell accounts, nonces or factors apart collapse into one generic answer.
 * `satisfies` makes this exhaustive: adding a code without mapping it fails typecheck.
 */
export const PUBLIC_ERROR_CODE = {
  MALFORMED_MESSAGE: 'MALFORMED_MESSAGE',
  UNEXPECTED_STEP: 'UNEXPECTED_STEP',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  NONCE_U_MISMATCH: 'NONCE_U_MISMATCH',
  PK_ENC_KEY_MISMATCH: 'PK_ENC_KEY_MISMATCH',
  SERVER_ID_MISMATCH: 'SERVER_ID_MISMATCH',
  DECRYPTION_FAILED: 'AUTH_FAILED',
  STALE_NONCE: 'AUTH_FAILED',
  AUTH_FAILED: 'AUTH_FAILED',
  FACTOR_NOT_OFFERED: 'AUTH_FAILED',
  SECOND_FACTOR_FAILED: 'SECOND_FACTOR_FAILED',
  ATTEMPTS_EXHAUSTED: 'ATTEMPTS_EXHAUSTED',
  PENDING_EXPIRED: 'PENDING_EXPIRED',
  REPLAY_DETECTED: 'AUTH_FAILED',
  RATE_LIMITED: 'RATE_LIMITED',
  KEY_ROTATED: 'PENDING_EXPIRED',
  INTERNAL: 'INTERNAL',
} as const satisfies Record<ErrorCode, ErrorCode>;

export function toPublicErrorCode(code: ErrorCode): ErrorCode {
  return PUBLIC_ERROR_CODE[code];
}

/**
 * The message is the code and nothing else. It never interpolates received
 * input, and it never keeps zod issues (which can echo a rejected password).
 * Only issue paths and codes are retained, as `issues`.
 */
export class ProtocolError extends Error {
  readonly code: ErrorCode;
  readonly issues: readonly { path: string; code: string }[];

  constructor(code: ErrorCode, issues: readonly { path: string; code: string }[] = []) {
    super(code);
    this.name = 'ProtocolError';
    this.code = code;
    this.issues = issues;
  }

  toJSON(): { code: ErrorCode } {
    return { code: this.code };
  }
}

/** Reduce a ZodError to paths and issue codes only, dropping messages and received values. */
export function safeIssues(error: z.ZodError): { path: string; code: string }[] {
  return error.issues.map((i) => ({ path: i.path.map(String).join('.'), code: i.code }));
}
