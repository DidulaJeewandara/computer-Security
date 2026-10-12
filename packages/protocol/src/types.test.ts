// [RMR] Round trip of every message and plaintext; unknown fields and malformed input rejected
import { describe, expect, it } from 'vitest';
import {
  ChallengePlaintextSchema,
  ERROR_CODES,
  ErrorCodeSchema,
  NOTATION,
  PUBLIC_ERROR_CODE,
  PasswordPlaintextSchema,
  ProtocolError,
  ResponsePlaintextSchema,
  ResultPlaintextSchema,
  decodeMessage,
  decodePlaintext,
  encodeMessage,
  encodePlaintext,
  encodeSigmaSPayload,
  toBase64Url,
  type Message,
} from './index.js';

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const box = (ctLen = 40) => ({ iv: fill(12, 7), ct: fill(ctLen, 8) });

const messages: Record<string, Message> = {
  hello: {
    type: 'hello',
    uId: 'alice',
    sId: NOTATION.S_ID,
    nonceU: fill(32, 1),
    pkEncKeyU: fill(32, 2),
  },
  server_hello: {
    type: 'server_hello',
    sigmaS: fill(64, 3),
    signed: encodeSigmaSPayload({ nonceU: fill(32, 1), pkEncKeyU: fill(32, 2), sId: NOTATION.S_ID }),
    c1: { enc: fill(32, 4), ct: fill(48, 5) },
    nonceS: fill(32, 6),
  },
  password: { type: 'password', c2: box() },
  challenge: { type: 'challenge', c3: box() },
  response: { type: 'response', c4: box(200) },
  result: { type: 'result', c6: box(17) },
};

const assertion = {
  id: 'abc_-123',
  rawId: 'abc_-123',
  type: 'public-key' as const,
  clientExtensionResults: {},
  response: { clientDataJSON: 'Y2xpZW50', authenticatorData: 'YXV0aA', signature: 'c2ln', userHandle: 'dXNlcg' },
};

function expectMalformed(fn: () => unknown) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe('MALFORMED_MESSAGE');
    return;
  }
  throw new Error('expected ProtocolError(MALFORMED_MESSAGE)');
}

describe('round trip: all six protocol messages', () => {
  for (const [name, msg] of Object.entries(messages)) {
    it(`${name}: domain -> wire -> domain`, () => {
      expect(decodeMessage(encodeMessage(msg))).toEqual(msg);
    });
    it(`${name}: wire -> domain -> wire is byte-identical`, () => {
      const wire = encodeMessage(msg);
      expect(encodeMessage(decodeMessage(wire))).toBe(wire);
    });
  }
});

describe('round trip: decrypted plaintexts', () => {
  it('c2 plaintext (password | nonce_s)', () => {
    const v = { password: 'correct horse battery staple', nonceS: fill(32, 9) };
    expect(decodePlaintext(PasswordPlaintextSchema, encodePlaintext(PasswordPlaintextSchema, v))).toEqual(v);
  });
  it('c3 plaintext (nonce_s2)', () => {
    const v = { nonceS2: fill(32, 10) };
    expect(decodePlaintext(ChallengePlaintextSchema, encodePlaintext(ChallengePlaintextSchema, v))).toEqual(v);
  });
  it('c4 plaintext, form 5b (otp)', () => {
    const v = { form: 'otp' as const, otp: '012345' };
    expect(decodePlaintext(ResponsePlaintextSchema, encodePlaintext(ResponsePlaintextSchema, v))).toEqual(v);
  });
  it('c4 plaintext, form 5a (webauthn assertion)', () => {
    const v = { form: 'webauthn' as const, assertion };
    expect(decodePlaintext(ResponsePlaintextSchema, encodePlaintext(ResponsePlaintextSchema, v))).toEqual(v);
  });
  it('step 6 plaintext (OK)', () => {
    const v = { status: 'OK' as const };
    expect(decodePlaintext(ResultPlaintextSchema, encodePlaintext(ResultPlaintextSchema, v))).toEqual(v);
  });
});

describe('unknown fields are rejected', () => {
  for (const [name, msg] of Object.entries(messages)) {
    it(`message ${name}`, () => {
      const wire = JSON.parse(encodeMessage(msg));
      expectMalformed(() => decodeMessage(JSON.stringify({ ...wire, extra: 1 })));
    });
  }

  it('inside c1', () => {
    const wire = JSON.parse(encodeMessage(messages.server_hello!));
    wire.c1.extra = 'x';
    expectMalformed(() => decodeMessage(JSON.stringify(wire)));
  });

  it('inside an AEAD box', () => {
    const wire = JSON.parse(encodeMessage(messages.password!));
    wire.c2.extra = 'x';
    expectMalformed(() => decodeMessage(JSON.stringify(wire)));
  });

  it('plaintexts', () => {
    const pw = JSON.parse(new TextDecoder().decode(encodePlaintext(PasswordPlaintextSchema, { password: 'pw', nonceS: fill(32, 1) })));
    expectMalformed(() => decodePlaintext(PasswordPlaintextSchema, new TextEncoder().encode(JSON.stringify({ ...pw, extra: 1 }))));
    expectMalformed(() => decodePlaintext(ChallengePlaintextSchema, new TextEncoder().encode(JSON.stringify({ nonceS2: toBase64Url(fill(32, 1)), extra: 1 }))));
    expectMalformed(() => decodePlaintext(ResponsePlaintextSchema, new TextEncoder().encode(JSON.stringify({ form: 'otp', otp: '123456', extra: 1 }))));
    expectMalformed(() => decodePlaintext(ResultPlaintextSchema, new TextEncoder().encode(JSON.stringify({ status: 'OK', extra: 1 }))));
  });

  it('inside a webauthn assertion and its response', () => {
    const enc = (a: unknown) => new TextEncoder().encode(JSON.stringify({ form: 'webauthn', assertion: a }));
    expectMalformed(() => decodePlaintext(ResponsePlaintextSchema, enc({ ...assertion, extra: 1 })));
    expectMalformed(() => decodePlaintext(ResponsePlaintextSchema, enc({ ...assertion, response: { ...assertion.response, extra: 1 } })));
  });

  it('an own __proto__ key from JSON.parse', () => {
    const wire = encodeMessage(messages.password!);
    expectMalformed(() => decodeMessage(wire.replace('{', '{"__proto__":{"admin":true},')));
  });

  it('an unknown message type', () => {
    expectMalformed(() => decodeMessage(JSON.stringify({ type: 'hello2' })));
  });
});

describe('malformed input is rejected', () => {
  const helloWire = () => JSON.parse(encodeMessage(messages.hello!));

  it('wrong-length nonce, key and signature', () => {
    for (const [field, len] of [['nonceU', 31], ['nonceU', 33], ['pkEncKeyU', 31], ['pkEncKeyU', 33]] as const) {
      expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), [field]: toBase64Url(fill(len, 1)) })));
    }
    const sh = JSON.parse(encodeMessage(messages.server_hello!));
    expectMalformed(() => decodeMessage(JSON.stringify({ ...sh, sigmaS: toBase64Url(fill(63, 1)) })));
  });

  it('padded and non-canonical base64url', () => {
    expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), nonceU: toBase64Url(fill(32, 1)) + '=' })));
    expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), nonceU: toBase64Url(fill(32, 1)).replace(/.$/, 'B') })));
    expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), nonceU: '+'.repeat(43) })));
  });

  it('oversized message, bad JSON, wrong JSON types', () => {
    expectMalformed(() => decodeMessage('x'.repeat(20_000)));
    expectMalformed(() => decodeMessage('{not json'));
    expectMalformed(() => decodeMessage('null'));
    expectMalformed(() => decodeMessage('[]'));
    expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), uId: 5 })));
    expectMalformed(() => decodeMessage(JSON.stringify({ ...helloWire(), uId: '' })));
  });

  it('OTP must be exactly six decimal digits', () => {
    const enc = (otp: unknown) => new TextEncoder().encode(JSON.stringify({ form: 'otp', otp }));
    for (const bad of ['12345', '1234567', 'abcdef', '12345a', ' 12345', '１２３４５６', 123456]) {
      expectMalformed(() => decodePlaintext(ResponsePlaintextSchema, enc(bad)));
    }
  });

  it('step 6 plaintext must be exactly OK', () => {
    expectMalformed(() => decodePlaintext(ResultPlaintextSchema, new TextEncoder().encode('{"status":"FAIL"}')));
  });

  it('invalid UTF-8 plaintext', () => {
    expectMalformed(() => decodePlaintext(ResultPlaintextSchema, Uint8Array.from([0x7b, 0xff, 0x7d])));
  });
});

describe('errors never leak what was received', () => {
  const MARKER = 'SECRET-marker-123';

  it('a rejected password plaintext carries no part of the password', () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ password: MARKER, nonceS: 'short', extra: MARKER }));
    let err: unknown;
    try {
      decodePlaintext(PasswordPlaintextSchema, bytes);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ProtocolError);
    const e = err as ProtocolError;
    const everything = [e.message, e.stack, JSON.stringify(e), JSON.stringify(e.issues), String((e as { cause?: unknown }).cause)].join('\n');
    expect(everything).not.toContain(MARKER);
    expect(e.message).toBe('MALFORMED_MESSAGE');
  });

  it('a password over the length limit is rejected without echoing it', () => {
    const long = 'p'.repeat(2000);
    try {
      decodePlaintext(PasswordPlaintextSchema, new TextEncoder().encode(JSON.stringify({ password: long, nonceS: toBase64Url(fill(32, 1)) })));
    } catch (e) {
      expect(JSON.stringify((e as ProtocolError).issues)).not.toContain('ppp');
      return;
    }
    throw new Error('expected rejection');
  });
});

describe('error codes are a closed set', () => {
  it('the schema accepts every listed code and nothing else', () => {
    for (const c of ERROR_CODES) expect(ErrorCodeSchema.safeParse(c).success).toBe(true);
    expect(ErrorCodeSchema.safeParse('SOMETHING_ELSE').success).toBe(false);
    expect(ErrorCodeSchema.safeParse('').success).toBe(false);
  });

  it('codes are unique', () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
  });

  it('every code has a public mapping that is itself a valid code', () => {
    expect(Object.keys(PUBLIC_ERROR_CODE).sort()).toEqual([...ERROR_CODES].sort());
    for (const v of Object.values(PUBLIC_ERROR_CODE)) expect(ErrorCodeSchema.safeParse(v).success).toBe(true);
  });

  it('internal reasons that would aid enumeration collapse to AUTH_FAILED', () => {
    for (const c of ['STALE_NONCE', 'DECRYPTION_FAILED', 'FACTOR_NOT_OFFERED', 'REPLAY_DETECTED'] as const) {
      expect(PUBLIC_ERROR_CODE[c]).toBe('AUTH_FAILED');
    }
  });
});

describe('notation constants match the shared context', () => {
  it('has the fixed values', () => {
    expect(NOTATION.S_ID).toBe('auth.deltaforce.lk');
    expect(NOTATION.NONCE_BYTES).toBe(32);
    expect(NOTATION.SESSION_ID_BYTES).toBe(32);
    expect(NOTATION.OTP).toEqual({ DIGITS: 6, TTL_SECONDS: 180 });
    expect(NOTATION.PENDING_AUTH).toEqual({ TTL_SECONDS: 600, MAX_VERIFY_ATTEMPTS: 5 });
    expect(NOTATION.ARGON2ID).toEqual({ MEMORY_KIB: 19456, ITERATIONS: 2, PARALLELISM: 1, SALT_BYTES: 16 });
    expect(NOTATION.RECOVERY.COUNT).toBe(10);
    expect(NOTATION.RECOVERY.LENGTH).toBe(10);
    expect(NOTATION.RECOVERY.ALPHABET).toHaveLength(32);
    expect(new Set(NOTATION.RECOVERY.ALPHABET).size).toBe(32);
    for (const ambiguous of 'ILOU') expect(NOTATION.RECOVERY.ALPHABET).not.toContain(ambiguous);
    expect(NOTATION.HPKE).toEqual({ KEM_ID: 0x0020, KDF_ID: 0x0001, AEAD_ID: 0x0002 });
  });

  it('is frozen', () => {
    expect(Object.isFrozen(NOTATION)).toBe(true);
  });
});
