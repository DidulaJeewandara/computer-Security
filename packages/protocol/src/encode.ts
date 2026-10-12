// [RMR] Canonical length-prefixed encoder/decoder for the bytes sigma_s signs
import { NOTATION, IMPLEMENTATION_LIMITS } from './constants.js';
import { utf8DecodeStrict, utf8Encode } from './bytes.js';
import { ProtocolError } from './errors.js';

/*
 * WIRE FORMAT
 *
 *   encodeFields([f1, ..., fn]) = u32be(len f1) || f1 || ... || u32be(len fn) || fn
 *
 * WHY THIS CANNOT COLLIDE
 *   decodeFields(encodeFields(fs), fs.length) = fs for every list of byte
 *   strings fs (the decoder reads a length, then exactly that many bytes, and
 *   repeats). A function with a left inverse is injective, so two different
 *   field lists can never produce the same bytes. Plain concatenation has no
 *   such inverse: ("ab","c") and ("a","bc") both give "abc". The length prefix
 *   is what makes the boundary between fields part of the signed data.
 *
 * The decoder is strict: it rejects a truncated prefix, a length that runs past
 * the input, a field count other than the one expected, and trailing bytes, so
 * there is exactly one byte string per field list and one field list per
 * accepted byte string.
 *
 * RMR-9: the OTP HMAC input nonce_s2 | U_id | channel has the same ambiguity
 * (U_id is variable length). Build it with encodeFields, not with "|".
 */

const MAX_FIELD_BYTES = 0xffff_ffff;

export function encodeFields(fields: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const f of fields) {
    if (f.length > MAX_FIELD_BYTES) throw new ProtocolError('MALFORMED_MESSAGE');
    total += 4 + f.length;
  }
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const f of fields) {
    view.setUint32(offset, f.length, false);
    out.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return out;
}

export function decodeFields(bytes: Uint8Array, expectedCount: number): Uint8Array[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fields: Uint8Array[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (fields.length === expectedCount) throw new ProtocolError('MALFORMED_MESSAGE'); // extra field or trailing bytes
    if (bytes.length - offset < 4) throw new ProtocolError('MALFORMED_MESSAGE'); // truncated prefix
    const len = view.getUint32(offset, false);
    offset += 4;
    if (len > bytes.length - offset) throw new ProtocolError('MALFORMED_MESSAGE'); // length overrun
    fields.push(bytes.slice(offset, offset + len));
    offset += len;
  }
  if (fields.length !== expectedCount) throw new ProtocolError('MALFORMED_MESSAGE'); // missing field
  return fields;
}

/** The three fields sigma_s covers. Signing the nonce alone is the Lowe weakness. */
export interface SigmaSPayload {
  nonceU: Uint8Array;
  pkEncKeyU: Uint8Array;
  sId: string;
}

// Lowercase DNS hostname, labels 1-63 chars, no leading/trailing hyphen.
const HOSTNAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function validate(p: SigmaSPayload, sIdBytes: Uint8Array): void {
  if (p.nonceU.length !== NOTATION.NONCE_BYTES) throw new ProtocolError('MALFORMED_MESSAGE');
  if (p.pkEncKeyU.length !== NOTATION.X25519_PUBLIC_KEY_BYTES) throw new ProtocolError('MALFORMED_MESSAGE');
  if (sIdBytes.length === 0 || sIdBytes.length > IMPLEMENTATION_LIMITS.S_ID_MAX_BYTES || !HOSTNAME.test(p.sId)) {
    throw new ProtocolError('MALFORMED_MESSAGE');
  }
}

/**
 * Bytes sigma_s signs: LP(nonce_u) || LP(PKEncKey_u) || LP(S_id).
 * Validates before encoding so the signer refuses to sign anything malformed.
 */
export function encodeSigmaSPayload(p: SigmaSPayload): Uint8Array {
  const sId = utf8Encode(p.sId);
  validate(p, sId);
  return encodeFields([p.nonceU, p.pkEncKeyU, sId]);
}

export function decodeSigmaSPayload(bytes: Uint8Array): SigmaSPayload {
  const [nonceU, pkEncKeyU, sIdBytes] = decodeFields(bytes, 3) as [Uint8Array, Uint8Array, Uint8Array];
  let sId: string;
  try {
    sId = utf8DecodeStrict(sIdBytes);
  } catch {
    throw new ProtocolError('MALFORMED_MESSAGE');
  }
  const payload = { nonceU, pkEncKeyU, sId };
  validate(payload, sIdBytes);
  return payload;
}
