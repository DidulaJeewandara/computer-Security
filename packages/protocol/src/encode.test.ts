// [RMR] Round trip; unknown field rejected; no two field triples encode to the same bytes
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { bytesEqual, toBase64Url, fromBase64Url, utf8Encode } from './bytes.js';
import { decodeFields, decodeSigmaSPayload, encodeFields, encodeSigmaSPayload } from './encode.js';
import { NOTATION } from './constants.js';
import { ProtocolError } from './errors.js';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const u = (...xs: number[]) => Uint8Array.from(xs);

const goodPayload = () => ({ nonceU: fill(32, 1), pkEncKeyU: fill(32, 2), sId: NOTATION.S_ID });

function throwsMalformed(fn: () => unknown) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe('MALFORMED_MESSAGE');
    return;
  }
  throw new Error('expected ProtocolError(MALFORMED_MESSAGE)');
}

describe('sigma_s payload: round trip', () => {
  it('decode(encode(p)) returns the same three fields', () => {
    const p = goodPayload();
    const back = decodeSigmaSPayload(encodeSigmaSPayload(p));
    expect(hex(back.nonceU)).toBe(hex(p.nonceU));
    expect(hex(back.pkEncKeyU)).toBe(hex(p.pkEncKeyU));
    expect(back.sId).toBe(p.sId);
  });

  it('has the documented layout: u32be(len) || field, three times', () => {
    const bytes = encodeSigmaSPayload(goodPayload());
    expect(bytes.length).toBe(4 + 32 + 4 + 32 + 4 + NOTATION.S_ID.length);
    expect(hex(bytes.slice(0, 4))).toBe('00000020');
    expect(hex(bytes.slice(36, 40))).toBe('00000020');
    expect(hex(bytes.slice(72, 76))).toBe('00000012'); // 18 = "auth.deltaforce.lk"
  });

  it('all three fields change the signed bytes, so none can be dropped', () => {
    const base = hex(encodeSigmaSPayload(goodPayload()));
    expect(hex(encodeSigmaSPayload({ ...goodPayload(), nonceU: fill(32, 9) }))).not.toBe(base);
    expect(hex(encodeSigmaSPayload({ ...goodPayload(), pkEncKeyU: fill(32, 9) }))).not.toBe(base);
    expect(hex(encodeSigmaSPayload({ ...goodPayload(), sId: 'other.example.lk' }))).not.toBe(base);
  });

  it('signer refuses to encode malformed fields', () => {
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), nonceU: fill(31, 1) }));
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), pkEncKeyU: fill(33, 1) }));
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), sId: '' }));
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), sId: 'Auth.DeltaForce.lk' }));
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), sId: 'a b' }));
    throwsMalformed(() => encodeSigmaSPayload({ ...goodPayload(), sId: 'a'.repeat(254) }));
  });
});

describe('decoder is strict', () => {
  const good = () => encodeSigmaSPayload(goodPayload());

  it('rejects a truncated length prefix', () => {
    throwsMalformed(() => decodeFields(good().slice(0, 2), 3));
    throwsMalformed(() => decodeFields(u(0, 0, 0, 1, 7, 0, 0), 2));
  });

  it('rejects a length that runs past the end of the input', () => {
    throwsMalformed(() => decodeFields(u(0, 0, 0, 5, 1, 2), 1));
    throwsMalformed(() => decodeFields(u(0xff, 0xff, 0xff, 0xff), 1));
  });

  it('rejects trailing bytes', () => {
    const g = good();
    const withTrailer = new Uint8Array(g.length + 1);
    withTrailer.set(g);
    throwsMalformed(() => decodeSigmaSPayload(withTrailer));
  });

  it('rejects a fourth field and a missing field', () => {
    throwsMalformed(() => decodeSigmaSPayload(encodeFields([fill(32, 1), fill(32, 2), utf8Encode('a.b'), u(1)])));
    throwsMalformed(() => decodeSigmaSPayload(encodeFields([fill(32, 1), fill(32, 2)])));
    throwsMalformed(() => decodeFields(new Uint8Array(0), 3));
  });

  it('rejects wrong-size nonce or key even when the framing is valid', () => {
    throwsMalformed(() => decodeSigmaSPayload(encodeFields([fill(31, 1), fill(32, 2), utf8Encode(NOTATION.S_ID)])));
    throwsMalformed(() => decodeSigmaSPayload(encodeFields([fill(32, 1), fill(33, 2), utf8Encode(NOTATION.S_ID)])));
  });

  it('rejects invalid UTF-8 in S_id', () => {
    throwsMalformed(() => decodeSigmaSPayload(encodeFields([fill(32, 1), fill(32, 2), u(0xff, 0xfe, 0xfd)])));
  });

  it('rejects a field boundary moved by one byte (the Lowe-style shift)', () => {
    // Same 3 x ... bytes as a valid payload but with the first boundary moved: 31 | 33 split.
    const concat = new Uint8Array([...fill(32, 1), ...fill(32, 2)]);
    const shifted = encodeFields([concat.slice(0, 31), concat.slice(31), utf8Encode(NOTATION.S_ID)]);
    throwsMalformed(() => decodeSigmaSPayload(shifted));
    expect(hex(shifted)).not.toBe(hex(good()));
  });
});

describe('no two field triples encode to the same bytes', () => {
  it('plain concatenation collides, the length-prefixed encoding does not', () => {
    const cat = (...fs: Uint8Array[]) => hex(new Uint8Array(fs.flatMap((f) => [...f])));
    const a = [utf8Encode('ab'), utf8Encode('c'), utf8Encode('')];
    const b = [utf8Encode('a'), utf8Encode('bc'), utf8Encode('')];
    expect(cat(...a)).toBe(cat(...b)); // the bug the prefix removes
    expect(hex(encodeFields(a))).not.toBe(hex(encodeFields(b)));
  });

  it('exhaustive: every triple over {0x00,0x01,0xff} with total length <= 5 is distinct', () => {
    const alphabet = [0x00, 0x01, 0xff];
    const strings: Uint8Array[] = [];
    const grow = (cur: number[]) => {
      strings.push(Uint8Array.from(cur));
      if (cur.length === 5) return;
      for (const a of alphabet) grow([...cur, a]);
    };
    grow([]);

    const seen = new Set<string>();
    let triples = 0;
    for (const x of strings)
      for (const y of strings) {
        if (x.length + y.length > 5) continue;
        for (const z of strings) {
          if (x.length + y.length + z.length > 5) continue;
          triples++;
          seen.add(hex(encodeFields([x, y, z])));
        }
      }
    expect(triples).toBeGreaterThan(1000);
    expect(seen.size).toBe(triples);
  });

  const field = fc.uint8Array({ maxLength: 40 });

  it('property: decodeFields(encodeFields(t), 3) equals t (left inverse, so injective)', () => {
    fc.assert(
      fc.property(fc.tuple(field, field, field), (t) => {
        const back = decodeFields(encodeFields(t), 3);
        return back.every((f, i) => bytesEqual(f, t[i]!));
      }),
    );
  });

  it('property: different triples never share an encoding', () => {
    fc.assert(
      fc.property(fc.tuple(field, field, field), fc.tuple(field, field, field), (t1, t2) => {
        const same = t1.every((f, i) => bytesEqual(f, t2[i]!));
        return same || hex(encodeFields(t1)) !== hex(encodeFields(t2));
      }),
    );
  });

  it('property: valid sigma_s payloads round trip and differ iff a field differs', () => {
    const payload = fc.record({
      nonceU: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      pkEncKeyU: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      sId: fc.constantFrom('auth.deltaforce.lk', 'other.example.lk', 'a', 'a-b.c'),
    });
    fc.assert(
      fc.property(payload, payload, (p, q) => {
        const back = decodeSigmaSPayload(encodeSigmaSPayload(p));
        const same = bytesEqual(p.nonceU, q.nonceU) && bytesEqual(p.pkEncKeyU, q.pkEncKeyU) && p.sId === q.sId;
        const roundTrips =
          bytesEqual(back.nonceU, p.nonceU) && bytesEqual(back.pkEncKeyU, p.pkEncKeyU) && back.sId === p.sId;
        return roundTrips && (same || hex(encodeSigmaSPayload(p)) !== hex(encodeSigmaSPayload(q)));
      }),
    );
  });
});

describe('base64url is canonical', () => {
  it('round trips arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (b) => {
        const back = fromBase64Url(toBase64Url(b));
        return back !== null && bytesEqual(back, b);
      }),
    );
  });

  it('rejects padding, wrong alphabet, bad length and non-zero trailing bits', () => {
    expect(fromBase64Url('AA==')).toBeNull();
    expect(fromBase64Url('A+A')).toBeNull();
    expect(fromBase64Url('A/A')).toBeNull();
    expect(fromBase64Url('AAAAA')).toBeNull(); // length = 1 mod 4
    expect(fromBase64Url('AB')).toBeNull(); // 'AB' leaves non-zero trailing bits; canonical form is 'AA'
    expect(fromBase64Url('AAB')).toBeNull();
    expect(fromBase64Url('AA')).not.toBeNull();
  });
});
