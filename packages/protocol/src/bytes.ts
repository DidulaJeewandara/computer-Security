// [RMR] Byte helpers that run in Node and the browser (no Buffer)

const B64URL = /^[A-Za-z0-9_-]*$/;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Record<string, number> = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));

/** Unpadded base64url. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/**
 * Strict, canonical decode: unpadded base64url only, and the unused trailing
 * bits must be zero, so every byte string has exactly one accepted spelling.
 * Returns null on any violation.
 */
export function fromBase64Url(text: string): Uint8Array | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < text.length; i += 4) {
    const n =
      (LOOKUP[text[i]!]! << 18) | (LOOKUP[text[i + 1]!]! << 12) | (LOOKUP[text[i + 2]!]! << 6) | LOOKUP[text[i + 3]!]!;
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  const rest = text.length - i;
  if (rest === 2) {
    const n = (LOOKUP[text[i]!]! << 18) | (LOOKUP[text[i + 1]!]! << 12);
    if ((n & 0xffff) !== 0) return null; // non-zero trailing bits
    out[o++] = (n >> 16) & 255;
  } else if (rest === 3) {
    const n = (LOOKUP[text[i]!]! << 18) | (LOOKUP[text[i + 1]!]! << 12) | (LOOKUP[text[i + 2]!]! << 6);
    if ((n & 0xff) !== 0) return null;
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
  }
  return out;
}

/** Constant-time over the shorter length plus a length check folded into the result. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Throws on invalid UTF-8; callers convert to ProtocolError. */
export function utf8DecodeStrict(bytes: Uint8Array): string {
  return strictDecoder.decode(bytes);
}
