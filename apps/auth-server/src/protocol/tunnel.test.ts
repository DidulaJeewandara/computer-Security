// [RMR] All three fields are inside the signature; a signature over the nonce alone fails
import { beforeEach, describe, expect, it } from 'vitest';
import {
  C1_INFO,
  HelloSchema,
  NOTATION,
  ServerHelloSchema,
  decodeSigmaSPayload,
  generateEncKeyPair,
  hpkeOpen,
  randomNonce,
  verifySigmaS,
  type EncKeyPair,
} from '@deltaforce/protocol';
import { handleHello, type PendingAuthRecord, type PendingStore } from './tunnel.js';

const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const rejectsWith = (p: Promise<unknown>, code: string) => expect(p).rejects.toMatchObject({ code, message: code });

let serverKeys: CryptoKeyPair;
let store: Map<string, { record: PendingAuthRecord; ttl: number }>;
let pending: PendingStore;
let client: EncKeyPair;

const signer = () => ({ keyId: 'test-key-1', privateKey: serverKeys.privateKey });
const helloWire = (over: Record<string, unknown> = {}) => ({
  ...HelloSchema.encode({
    type: 'hello',
    uId: 'alice@example.com',
    sId: NOTATION.S_ID,
    nonceU: nonceU,
    pkEncKeyU: client.publicKey,
  }),
  ...over,
});
let nonceU: Uint8Array;

beforeEach(async () => {
  serverKeys = (await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  store = new Map();
  pending = { create: async (id, record, ttl) => void store.set(id, { record, ttl }) };
  client = await generateEncKeyPair();
  nonceU = randomNonce();
});

// What the client would see: the message as JSON over the wire.
const onTheWire = (m: unknown) => ServerHelloSchema.decode(JSON.parse(JSON.stringify(m)));

describe('steps 1 and 2', () => {
  it('signs all three fields: the captured transcript decodes to nonce_u, PKEncKey_u and S_id', async () => {
    const { message } = await handleHello(helloWire(), { signer: signer(), pending });
    const { signed, sigmaS } = onTheWire(message);

    const covered = decodeSigmaSPayload(signed);
    expect(toHex(covered.nonceU)).toBe(toHex(nonceU));
    expect(toHex(covered.pkEncKeyU)).toBe(toHex(client.publicKey));
    expect(covered.sId).toBe(NOTATION.S_ID);

    expect(await verifySigmaS(serverKeys.publicKey, signed, sigmaS)).toBe(true);
  });

  it('seals the session key to PKEncKey_u as c1, bound to the signed bytes', async () => {
    const { pendingId, message } = await handleHello(helloWire(), { signer: signer(), pending });
    const { signed, c1 } = onTheWire(message);
    const key = await hpkeOpen(client, C1_INFO, signed, c1);
    expect(toHex(key)).toBe(toHex(store.get(pendingId)!.record.sessionKey));
    // The same c1 is useless under any other handshake's signed bytes.
    const other = Uint8Array.from(signed);
    other[other.length - 1] = other[other.length - 1]! ^ 1;
    await rejectsWith(hpkeOpen(client, C1_INFO, other, c1), 'DECRYPTION_FAILED');
    await rejectsWith(hpkeOpen(await generateEncKeyPair(), C1_INFO, signed, c1), 'DECRYPTION_FAILED');
  });

  it('stores everything in the pending record with the 10 minute TTL', async () => {
    const { pendingId, message } = await handleHello(helloWire(), { signer: signer(), pending, now: () => 1_000_000 });
    const { record, ttl } = store.get(pendingId)!;
    expect(ttl).toBe(NOTATION.PENDING_AUTH.TTL_SECONDS);
    expect(record).toMatchObject({
      uId: 'alice@example.com',
      keyId: 'test-key-1',
      state: 'AWAITING_PASSWORD',
      attempts: 0,
      expiresAt: 1_000_000 + 600_000,
    });
    expect(toHex(record.nonceU)).toBe(toHex(nonceU));
    expect(toHex(record.pkEncKeyU)).toBe(toHex(client.publicKey));
    expect(record.sessionKey.length).toBe(32);
    expect(record.nonceS2.length).toBe(32);
    expect(toHex(record.nonceS)).toBe(toHex(onTheWire(message).nonceS));
  });

  it('keeps nonce_s2 and the session key out of the message', async () => {
    const { pendingId, message } = await handleHello(helloWire(), { signer: signer(), pending });
    const { record } = store.get(pendingId)!;
    const text = JSON.stringify(message);
    expect(Object.keys(message).sort()).toEqual(['c1', 'nonceS', 'sigmaS', 'signed', 'type']);
    for (const secret of [record.nonceS2, record.sessionKey]) {
      expect(text).not.toContain(Buffer.from(secret).toString('base64url'));
    }
  });

  it('gives every hello its own key, nonces and pending id', async () => {
    const a = await handleHello(helloWire(), { signer: signer(), pending });
    const b = await handleHello(helloWire(), { signer: signer(), pending });
    expect(a.pendingId).not.toBe(b.pendingId);
    const [ra, rb] = [store.get(a.pendingId)!.record, store.get(b.pendingId)!.record];
    expect(toHex(ra.sessionKey)).not.toBe(toHex(rb.sessionKey));
    expect(toHex(ra.nonceS)).not.toBe(toHex(rb.nonceS));
    expect(toHex(ra.nonceS2)).not.toBe(toHex(rb.nonceS2));
    expect(toHex(ra.nonceS)).not.toBe(toHex(ra.nonceS2));
  });

  describe('rejections store nothing and say only the code', () => {
    const cases: [string, () => unknown, string][] = [
      ['unknown field', () => helloWire({ extra: 1 }), 'MALFORMED_MESSAGE'],
      ['missing field', () => ({ ...helloWire(), nonceU: undefined }), 'MALFORMED_MESSAGE'],
      ['short nonce_u', () => helloWire({ nonceU: 'AAAA' }), 'MALFORMED_MESSAGE'],
      ['wrong type', () => helloWire({ type: 'password' }), 'MALFORMED_MESSAGE'],
      ['not an object', () => 'hello', 'MALFORMED_MESSAGE'],
      ['null', () => null, 'MALFORMED_MESSAGE'],
      ['wrong S_id', () => helloWire({ sId: 'evil.example' }), 'SERVER_ID_MISMATCH'],
      [
        'all-zero PKEncKey_u',
        () => HelloSchema.encode({ type: 'hello', uId: 'a', sId: NOTATION.S_ID, nonceU, pkEncKeyU: new Uint8Array(32) }),
        'MALFORMED_MESSAGE',
      ],
    ];
    for (const [name, wire, code] of cases) {
      it(name, async () => {
        const err = await handleHello(wire(), { signer: signer(), pending }).catch((e: unknown) => e as Error);
        expect(err).toMatchObject({ code, message: code });
        expect(JSON.stringify(err)).toBe(`{"code":"${code}"}`);
        expect(store.size).toBe(0);
      });
    }
  });
});
