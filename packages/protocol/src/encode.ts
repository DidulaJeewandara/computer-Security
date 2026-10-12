// [RMR] Canonical length-prefixed encoder/decoder for the bytes sigma_s signs
import { NOTATION, IMPLEMENTATION_LIMITS } from './constants.js';
import { utf8DecodeStrict, utf8Encode } from './bytes.js';
import { ProtocolError } from './errors.js';

// Format: u32be(len) || field, per field.
// decode(encode(x)) == x, so two different field lists can never encode the same.
// Plain concat can: ("ab","c") and ("a","bc") both give "abc".
// TODO(RMR-9): use encodeFields for the OTP HMAC input too.

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

// All three are signed; signing the nonce alone is the Lowe weakness.
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

// Validates first so we never sign a malformed payload.
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
