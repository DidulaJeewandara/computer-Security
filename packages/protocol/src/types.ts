// [RMR] Types + zod schemas for the six messages, notation constants, closed set of error codes
import { z } from 'zod';
import { fromBase64Url, toBase64Url, utf8DecodeStrict, utf8Encode } from './bytes.js';
import { IMPLEMENTATION_LIMITS, NOTATION } from './constants.js';
import { ProtocolError, safeIssues } from './errors.js';

export * from './constants.js';
export * from './errors.js';

/**
 * Binary field on the wire: canonical unpadded base64url string <-> Uint8Array,
 * length in [min, max]. A codec, so one schema both decodes and encodes.
 */
export function bytesRange(min: number, max: number) {
  const bin = z.custom<Uint8Array>((v) => v instanceof Uint8Array);
  return z.codec(z.string().max(Math.ceil((max * 4) / 3) + 4), bin, {
    decode: (text, ctx) => {
      const b = fromBase64Url(text);
      if (b === null || b.length < min || b.length > max) {
        ctx.issues.push({ code: 'invalid_format', format: 'base64url', input: text });
        return z.NEVER;
      }
      return b;
    },
    encode: (b) => toBase64Url(b),
  });
}

export const bytes = (n: number) => bytesRange(n, n);

const nonce = () => bytes(NOTATION.NONCE_BYTES);
const MAX_BOX = IMPLEMENTATION_LIMITS.MESSAGE_MAX_BYTES;

/** AES-256-GCM box: 12-byte IV, ciphertext including the 16-byte tag. */
export const AeadBoxSchema = z.strictObject({
  iv: bytes(NOTATION.AES_GCM.IV_BYTES),
  ct: bytesRange(NOTATION.AES_GCM.TAG_BYTES, MAX_BOX),
});

/** HPKE-sealed session key (c1): encapsulated X25519 key and AEAD ciphertext. */
export const HpkeBoxSchema = z.strictObject({
  enc: bytes(NOTATION.HPKE_ENC_BYTES),
  ct: bytes(NOTATION.HPKE_SEALED_KEY_BYTES),
});

// ---- the six messages (outer, as sent inside TLS) ----------------------------

/** 1. u -> s : U_id, S_id, nonce_u, PKEncKey_u */
export const HelloSchema = z.strictObject({
  type: z.literal('hello'),
  uId: z.string().min(1).max(IMPLEMENTATION_LIMITS.U_ID_MAX_CHARS),
  sId: z.string().min(1).max(IMPLEMENTATION_LIMITS.S_ID_MAX_BYTES),
  nonceU: nonce(),
  pkEncKeyU: bytes(NOTATION.X25519_PUBLIC_KEY_BYTES),
});

/**
 * 2. s -> u : sigma_s, c1, nonce_s.
 * `signed` is the canonical encoding of (nonce_u, PKEncKey_u, S_id) that sigma_s
 * covers. The client verifies sigma_s over it, decodes it, then compares each
 * field with its own values, so each check can fail separately.
 */
export const ServerHelloSchema = z.strictObject({
  type: z.literal('server_hello'),
  sigmaS: bytes(NOTATION.SIGMA_S_BYTES),
  signed: bytesRange(12 + 2 * NOTATION.NONCE_BYTES + 1, 12 + 2 * NOTATION.NONCE_BYTES + IMPLEMENTATION_LIMITS.S_ID_MAX_BYTES),
  c1: HpkeBoxSchema,
  nonceS: nonce(),
});

/** 3. u -> s : c2 = Enc_key(password | nonce_s) */
export const PasswordMessageSchema = z.strictObject({ type: z.literal('password'), c2: AeadBoxSchema });

/** 4. s -> u : c3 = Enc_key(nonce_s2) */
export const ChallengeMessageSchema = z.strictObject({ type: z.literal('challenge'), c3: AeadBoxSchema });

/** 5. u -> s : c4 = Enc_key(sigma_u) (5a) or the OTP (5b) */
export const ResponseMessageSchema = z.strictObject({ type: z.literal('response'), c4: AeadBoxSchema });

/** 6. s -> u : Enc_key(OK) */
export const ResultMessageSchema = z.strictObject({ type: z.literal('result'), c6: AeadBoxSchema });

export const MessageSchema = z.discriminatedUnion('type', [
  HelloSchema,
  ServerHelloSchema,
  PasswordMessageSchema,
  ChallengeMessageSchema,
  ResponseMessageSchema,
  ResultMessageSchema,
]);

// ---- decrypted contents (zod-validated at the boundary, per house rules) -----

export const PasswordPlaintextSchema = z.strictObject({
  password: z.string().min(1).max(IMPLEMENTATION_LIMITS.PASSWORD_MAX_CHARS),
  nonceS: nonce(),
});

export const ChallengePlaintextSchema = z.strictObject({ nonceS2: nonce() });

const base64urlText = z.string().min(1).max(MAX_BOX).regex(/^[A-Za-z0-9_-]+$/);

/** WebAuthn AuthenticationResponseJSON. Only clientExtensionResults is open-ended. */
export const WebAuthnAssertionSchema = z.strictObject({
  id: base64urlText,
  rawId: base64urlText,
  type: z.literal('public-key'),
  authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()),
  response: z.strictObject({
    clientDataJSON: base64urlText,
    authenticatorData: base64urlText,
    signature: base64urlText,
    userHandle: base64urlText.optional(),
  }),
});

/** 5a is a WebAuthn assertion (challenge IS nonce_s2); 5b is the six-digit OTP. */
export const ResponsePlaintextSchema = z.discriminatedUnion('form', [
  z.strictObject({ form: z.literal('webauthn'), assertion: WebAuthnAssertionSchema }),
  z.strictObject({ form: z.literal('otp'), otp: z.string().regex(new RegExp(`^\\d{${NOTATION.OTP.DIGITS}}$`)) }),
]);

export const ResultPlaintextSchema = z.strictObject({ status: z.literal('OK') });

// ---- exported types: domain (decoded) and wire (as sent) ---------------------

export type Hello = z.output<typeof HelloSchema>;
export type ServerHello = z.output<typeof ServerHelloSchema>;
export type PasswordMessage = z.output<typeof PasswordMessageSchema>;
export type ChallengeMessage = z.output<typeof ChallengeMessageSchema>;
export type ResponseMessage = z.output<typeof ResponseMessageSchema>;
export type ResultMessage = z.output<typeof ResultMessageSchema>;
export type Message = z.output<typeof MessageSchema>;
export type WireMessage = z.input<typeof MessageSchema>;
export type AeadBox = z.output<typeof AeadBoxSchema>;
export type HpkeBox = z.output<typeof HpkeBoxSchema>;
export type PasswordPlaintext = z.output<typeof PasswordPlaintextSchema>;
export type ChallengePlaintext = z.output<typeof ChallengePlaintextSchema>;
export type ResponsePlaintext = z.output<typeof ResponsePlaintextSchema>;
export type ResultPlaintext = z.output<typeof ResultPlaintextSchema>;

// ---- JSON codecs. Every failure becomes ProtocolError, never a zod error -----

function checkSize(byteLength: number): void {
  if (byteLength > IMPLEMENTATION_LIMITS.MESSAGE_MAX_BYTES) throw new ProtocolError('MALFORMED_MESSAGE');
}

function parseWith<S extends z.ZodType>(schema: S, text: string): z.output<S> {
  checkSize(utf8Encode(text).length);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ProtocolError('MALFORMED_MESSAGE');
  }
  // JSON.parse output is untrusted; the schema is exactly what validates it.
  const result = z.safeDecode(schema, raw as z.input<S>);
  if (!result.success) throw new ProtocolError('MALFORMED_MESSAGE', safeIssues(result.error));
  return result.data;
}

function stringifyWith<S extends z.ZodType>(schema: S, value: z.output<S>): string {
  const result = z.safeEncode(schema, value);
  if (!result.success) throw new ProtocolError('MALFORMED_MESSAGE', safeIssues(result.error));
  const text = JSON.stringify(result.data);
  checkSize(utf8Encode(text).length);
  return text;
}

export const encodeMessage = (m: Message): string => stringifyWith(MessageSchema, m);
export const decodeMessage = (json: string): Message => parseWith(MessageSchema, json);

/** Inner plaintexts travel as UTF-8 JSON bytes, ready to be sealed with Enc_key. */
export function encodePlaintext<S extends z.ZodType>(schema: S, value: z.output<S>): Uint8Array {
  return utf8Encode(stringifyWith(schema, value));
}

export function decodePlaintext<S extends z.ZodType>(schema: S, bytes: Uint8Array): z.output<S> {
  checkSize(bytes.length);
  let text: string;
  try {
    text = utf8DecodeStrict(bytes);
  } catch {
    throw new ProtocolError('MALFORMED_MESSAGE');
  }
  return parseWith(schema, text);
}
