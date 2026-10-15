// [RMR] A signature over the nonce alone fails; every field is covered
import { beforeAll, describe, expect, it } from 'vitest';
import { encodeFields, encodeSigmaSPayload, type SigmaSPayload } from './encode.js';
import { NOTATION } from './constants.js';
import { generateEncKeyPair, randomNonce } from './crypto.js';
import { signSigmaS, verifySigmaS } from './sigma.js';

const subtle = globalThis.crypto.subtle;
const ECDSA = { name: 'ECDSA', hash: 'SHA-256' } as const;
const newKeys = () => subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as Promise<CryptoKeyPair>;
const flip = (b: Uint8Array, i: number) => {
  const c = Uint8Array.from(b);
  c[i] = c[i]! ^ 1;
  return c;
};

let keys: CryptoKeyPair;
let payload: SigmaSPayload;
beforeAll(async () => {
  keys = await newKeys();
  payload = { nonceU: randomNonce(), pkEncKeyU: (await generateEncKeyPair()).publicKey, sId: NOTATION.S_ID };
});

describe('sigma_s', () => {
  it('signs and verifies, in the 64-byte P1363 form', async () => {
    const { sigmaS, signed } = await signSigmaS(keys.privateKey, payload);
    expect(sigmaS.length).toBe(NOTATION.SIGMA_S_BYTES);
    expect(signed).toEqual(encodeSigmaSPayload(payload));
    expect(await verifySigmaS(keys.publicKey, signed, sigmaS)).toBe(true);
  });

  describe('channel binding', () => {
    it('a signature over the nonce alone fails verification', async () => {
      const full = encodeSigmaSPayload(payload);
      const raw = new Uint8Array(await subtle.sign(ECDSA, keys.privateKey, payload.nonceU as Uint8Array<ArrayBuffer>));
      const framed = new Uint8Array(
        await subtle.sign(ECDSA, keys.privateKey, encodeFields([payload.nonceU]) as Uint8Array<ArrayBuffer>),
      );
      expect(await verifySigmaS(keys.publicKey, full, raw)).toBe(false);
      expect(await verifySigmaS(keys.publicKey, full, framed)).toBe(false);
    });

    it('a signature that leaves out S_id fails against the full payload', async () => {
      const partial = encodeFields([payload.nonceU, payload.pkEncKeyU]);
      const sig = new Uint8Array(await subtle.sign(ECDSA, keys.privateKey, partial as Uint8Array<ArrayBuffer>));
      expect(await verifySigmaS(keys.publicKey, encodeSigmaSPayload(payload), sig)).toBe(false);
    });

    it('a signature that leaves out PKEncKey_u fails against the full payload', async () => {
      const partial = encodeFields([payload.nonceU, new TextEncoder().encode(payload.sId)]);
      const sig = new Uint8Array(await subtle.sign(ECDSA, keys.privateKey, partial as Uint8Array<ArrayBuffer>));
      expect(await verifySigmaS(keys.publicKey, encodeSigmaSPayload(payload), sig)).toBe(false);
    });

    it('does not verify for a swapped PKEncKey_u (Lowe-style substitution)', async () => {
      const attacker = (await generateEncKeyPair()).publicKey;
      const { sigmaS } = await signSigmaS(keys.privateKey, { ...payload, pkEncKeyU: attacker });
      const victim = encodeSigmaSPayload(payload);
      expect(await verifySigmaS(keys.publicKey, victim, sigmaS)).toBe(false);
    });

    it('does not verify for a different nonce_u or S_id', async () => {
      const { sigmaS } = await signSigmaS(keys.privateKey, payload);
      expect(await verifySigmaS(keys.publicKey, encodeSigmaSPayload({ ...payload, nonceU: randomNonce() }), sigmaS)).toBe(false);
      expect(await verifySigmaS(keys.publicKey, encodeSigmaSPayload({ ...payload, sId: 'evil.example' }), sigmaS)).toBe(false);
    });
  });

  describe('verification fails closed', () => {
    it('rejects a tampered signature, the wrong key, and a wrong-length signature', async () => {
      const { sigmaS, signed } = await signSigmaS(keys.privateKey, payload);
      expect(await verifySigmaS(keys.publicKey, signed, flip(sigmaS, 0))).toBe(false);
      expect(await verifySigmaS((await newKeys()).publicKey, signed, sigmaS)).toBe(false);
      expect(await verifySigmaS(keys.publicKey, signed, sigmaS.subarray(1))).toBe(false);
    });

    it('returns false, never throws, when signed has an extra or missing field or is garbage', async () => {
      const f = [payload.nonceU, payload.pkEncKeyU, new TextEncoder().encode(payload.sId)];
      for (const bad of [encodeFields([...f, new Uint8Array(1)]), encodeFields(f.slice(0, 2)), new Uint8Array(0), new Uint8Array(7)]) {
        const sig = new Uint8Array(await subtle.sign(ECDSA, keys.privateKey, bad as Uint8Array<ArrayBuffer>));
        expect(await verifySigmaS(keys.publicKey, bad, sig)).toBe(false);
      }
    });

    it('refuses to sign a malformed payload', async () => {
      await expect(signSigmaS(keys.privateKey, { ...payload, nonceU: new Uint8Array(8) })).rejects.toMatchObject({ code: 'MALFORMED_MESSAGE' });
    });
  });
});
