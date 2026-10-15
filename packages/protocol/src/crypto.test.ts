// [RMR] Known-answer tests; a message replayed in the other direction fails to decrypt
import { createDecipheriv, createCipheriv, hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { toBase64Url, utf8Encode } from './bytes.js';
import { MESSAGE_INDEX, NOTATION } from './constants.js';
import {
  deriveDirectionalKeys,
  deriveEncKeyPair,
  generateEncKeyPair,
  generateSessionKey,
  hpkeOpen,
  hpkeSeal,
  openMessage,
  randomNonce,
  sealMessage,
  sealWithEphemeral,
} from './crypto.js';

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const u32be = (n: number) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const rejectsWith = (p: Promise<unknown>, code: string) => expect(p).rejects.toMatchObject({ code, message: code });
const flip = (b: Uint8Array, i: number) => {
  const c = Uint8Array.from(b);
  c[i] = c[i]! ^ 1;
  return c;
};

describe('random', () => {
  it('nonces are 32 bytes and do not repeat', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const n = randomNonce();
      expect(n.length).toBe(NOTATION.NONCE_BYTES);
      seen.add(toBase64Url(n));
    }
    expect(seen.size).toBe(1000);
  });

  it('session keys are 32 bytes', () => {
    expect(generateSessionKey().length).toBe(32);
  });
});

describe('X25519', () => {
  // RFC 7748 section 6.1, through the same PKCS#8 import deriveEncKeyPair uses.
  const PREFIX = hex('302e020100300506032b656e04220420');
  const alicePriv = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bobPub = hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  it('matches the RFC 7748 shared secret', async () => {
    const pkcs8 = new Uint8Array([...PREFIX, ...alicePriv]);
    const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
    const pub = await crypto.subtle.importKey('raw', bobPub, { name: 'X25519' }, false, []);
    const out = await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
    expect(toHex(new Uint8Array(out))).toBe(shared);
  });

  it('generates a pair with a 32-byte public key and a private key that cannot be exported', async () => {
    const pair = await generateEncKeyPair();
    expect(pair.publicKey.length).toBe(32);
    expect(pair.privateKey.extractable).toBe(false);
    expect(toHex(pair.publicKey)).not.toBe(toHex((await generateEncKeyPair()).publicKey));
  });
});

describe('HPKE', () => {
  // RFC 9180 test vector, mode 0 (base), DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
  // From github.com/cfrg/draft-irtf-cfrg-hpke test-vectors.json (kem_id 32, kdf_id 1, aead_id 2), encryption 0.
  const kat = {
    info: hex('4f6465206f6e2061204772656369616e2055726e'),
    ikmR: hex('dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee'),
    ikmE: hex('2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9'),
    pkRm: '430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c',
    pkEm: '6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256',
    aad: hex('436f756e742d30'),
    pt: hex('4265617574792069732074727574682c20747275746820626561757479'),
    ct: 'e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a',
  };

  it('derives the vector key pairs from their ikm', async () => {
    expect(toHex((await deriveEncKeyPair(kat.ikmR)).publicKey)).toBe(kat.pkRm);
    expect(toHex((await deriveEncKeyPair(kat.ikmE)).publicKey)).toBe(kat.pkEm);
  });

  it('seals to the vector enc and ciphertext', async () => {
    const box = await sealWithEphemeral(
      hex(kat.pkRm),
      await deriveEncKeyPair(kat.ikmE),
      kat.info,
      kat.aad,
      kat.pt,
    );
    expect(toHex(box.enc)).toBe(kat.pkEm);
    expect(toHex(box.ct)).toBe(kat.ct);
  });

  it('opens the vector ciphertext', async () => {
    const recipient = await deriveEncKeyPair(kat.ikmR);
    const pt = await hpkeOpen(recipient, kat.info, kat.aad, { enc: hex(kat.pkEm), ct: hex(kat.ct) });
    expect(toHex(pt)).toBe(toHex(kat.pt));
  });

  describe('round trip and failures', () => {
    const info = utf8Encode('info');
    const aad = utf8Encode('aad');

    it('seals a session key to the sizes the c1 schema expects', async () => {
      const recipient = await generateEncKeyPair();
      const key = generateSessionKey();
      const box = await hpkeSeal(recipient.publicKey, info, aad, key);
      expect(box.enc.length).toBe(NOTATION.HPKE_ENC_BYTES);
      expect(box.ct.length).toBe(NOTATION.HPKE_SEALED_KEY_BYTES);
      expect(toHex(await hpkeOpen(recipient, info, aad, box))).toBe(toHex(key));
    });

    it('uses a fresh ephemeral key every time', async () => {
      const recipient = await generateEncKeyPair();
      const a = await hpkeSeal(recipient.publicKey, info, aad, generateSessionKey());
      const b = await hpkeSeal(recipient.publicKey, info, aad, generateSessionKey());
      expect(toHex(a.enc)).not.toBe(toHex(b.enc));
    });

    it('fails for the wrong recipient, info, aad, or a tampered box', async () => {
      const recipient = await generateEncKeyPair();
      const box = await hpkeSeal(recipient.publicKey, info, aad, generateSessionKey());
      await rejectsWith(hpkeOpen(await generateEncKeyPair(), info, aad, box), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, utf8Encode('other'), aad, box), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, info, utf8Encode('other'), box), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, info, aad, { enc: flip(box.enc, 0), ct: box.ct }), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, info, aad, { enc: box.enc, ct: flip(box.ct, 0) }), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, info, aad, { enc: box.enc, ct: flip(box.ct, 47) }), 'DECRYPTION_FAILED');
    });

    it('rejects an all-zero, low-order or wrong-length recipient key when sealing', async () => {
      const lowOrder = hex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800');
      for (const pk of [new Uint8Array(32), lowOrder, new Uint8Array(31), new Uint8Array(0)]) {
        await rejectsWith(hpkeSeal(pk, info, aad, generateSessionKey()), 'MALFORMED_MESSAGE');
      }
    });

    it('rejects an all-zero or short enc when opening', async () => {
      const recipient = await generateEncKeyPair();
      const ct = new Uint8Array(48);
      await rejectsWith(hpkeOpen(recipient, info, aad, { enc: new Uint8Array(32), ct }), 'DECRYPTION_FAILED');
      await rejectsWith(hpkeOpen(recipient, info, aad, { enc: new Uint8Array(5), ct }), 'DECRYPTION_FAILED');
    });
  });
});

describe('Enc_key', () => {
  const C2S = 'deltaforce/v1 enc_key client-to-server';
  const S2C = 'deltaforce/v1 enc_key server-to-client';
  const subkey = (root: Uint8Array, label: string) => Buffer.from(hkdfSync('sha256', root, new Uint8Array(0), label, 32));

  it('derives the subkeys with HKDF-SHA256 and the documented labels (checked against node:crypto)', async () => {
    const root = generateSessionKey();
    const keys = await deriveDirectionalKeys(root);
    for (const [index, label, key] of [
      [MESSAGE_INDEX.PASSWORD, C2S, keys.clientToServer],
      [MESSAGE_INDEX.CHALLENGE, S2C, keys.serverToClient],
    ] as const) {
      const pt = utf8Encode('hello');
      const box = await sealMessage(keys, index, pt);
      expect(box.iv.length).toBe(12);
      expect(box.ct.length).toBe(pt.length + 16);
      // Independent decrypt with the oracle key, AAD is the u32be message index.
      const d = createDecipheriv('aes-256-gcm', subkey(root, label), box.iv);
      d.setAAD(u32be(index));
      d.setAuthTag(box.ct.subarray(box.ct.length - 16));
      const out = Buffer.concat([d.update(box.ct.subarray(0, box.ct.length - 16)), d.final()]);
      expect(out.toString()).toBe('hello');
      expect(key.extractable).toBe(false);
    }
  });

  it('opens a box made independently with node:crypto', async () => {
    const root = generateSessionKey();
    const keys = await deriveDirectionalKeys(root);
    const iv = Buffer.from(randomNonce().subarray(0, 12));
    const c = createCipheriv('aes-256-gcm', subkey(root, S2C), iv);
    c.setAAD(u32be(MESSAGE_INDEX.RESULT));
    const ct = Buffer.concat([c.update('ok'), c.final(), c.getAuthTag()]);
    const pt = await openMessage(keys, MESSAGE_INDEX.RESULT, { iv, ct });
    expect(new TextDecoder().decode(pt)).toBe('ok');
  });

  it('round trips every Enc_key message', async () => {
    const keys = await deriveDirectionalKeys(generateSessionKey());
    for (const index of [MESSAGE_INDEX.PASSWORD, MESSAGE_INDEX.CHALLENGE, MESSAGE_INDEX.RESPONSE, MESSAGE_INDEX.RESULT]) {
      const pt = randomNonce();
      const box = await sealMessage(keys, index, pt);
      expect(toHex(await openMessage(keys, index, box))).toBe(toHex(pt));
    }
  });

  it('uses a fresh IV for each message, even for the same key and index', async () => {
    const keys = await deriveDirectionalKeys(generateSessionKey());
    const a = await sealMessage(keys, MESSAGE_INDEX.RESPONSE, utf8Encode('x'));
    const b = await sealMessage(keys, MESSAGE_INDEX.RESPONSE, utf8Encode('x'));
    expect(toHex(a.iv)).not.toBe(toHex(b.iv));
  });

  describe('replay', () => {
    it('a message captured in one direction fails to decrypt when replayed in the other', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const c2 = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      // Replayed as the server's step 4 message, then as the server's step 6 message.
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.CHALLENGE, c2), 'DECRYPTION_FAILED');
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.RESULT, c2), 'DECRYPTION_FAILED');

      const c3 = await sealMessage(keys, MESSAGE_INDEX.CHALLENGE, utf8Encode('secret'));
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.PASSWORD, c3), 'DECRYPTION_FAILED');
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.RESPONSE, c3), 'DECRYPTION_FAILED');
    });

    it('the index binds the message: same direction, different number fails', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const c2 = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.RESPONSE, c2), 'DECRYPTION_FAILED');
      const c4 = await sealMessage(keys, MESSAGE_INDEX.CHALLENGE, utf8Encode('secret'));
      await rejectsWith(openMessage(keys, MESSAGE_INDEX.RESULT, c4), 'DECRYPTION_FAILED');
    });

    it('the same bytes do not open under the other direction key, even at the right index', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const swapped = { clientToServer: keys.serverToClient, serverToClient: keys.clientToServer };
      const c2 = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      await rejectsWith(openMessage(swapped, MESSAGE_INDEX.PASSWORD, c2), 'DECRYPTION_FAILED');
    });

    it('a box from another session does not open', async () => {
      const a = await deriveDirectionalKeys(generateSessionKey());
      const b = await deriveDirectionalKeys(generateSessionKey());
      const c2 = await sealMessage(a, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      await rejectsWith(openMessage(b, MESSAGE_INDEX.PASSWORD, c2), 'DECRYPTION_FAILED');
    });
  });

  describe('tampering and bad input', () => {
    it('fails on a flipped bit in the iv, ciphertext or tag', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const box = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      await rejectsWith(openMessage(keys, 3, { iv: flip(box.iv, 0), ct: box.ct }), 'DECRYPTION_FAILED');
      await rejectsWith(openMessage(keys, 3, { iv: box.iv, ct: flip(box.ct, 0) }), 'DECRYPTION_FAILED');
      await rejectsWith(openMessage(keys, 3, { iv: box.iv, ct: flip(box.ct, box.ct.length - 1) }), 'DECRYPTION_FAILED');
    });

    it('fails on a wrong-sized iv or a ciphertext shorter than the tag', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const box = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('secret'));
      await rejectsWith(openMessage(keys, 3, { iv: box.iv.subarray(1), ct: box.ct }), 'DECRYPTION_FAILED');
      await rejectsWith(openMessage(keys, 3, { iv: box.iv, ct: new Uint8Array(15) }), 'DECRYPTION_FAILED');
    });

    it('refuses messages that are not under Enc_key', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      for (const index of [0, MESSAGE_INDEX.HELLO, MESSAGE_INDEX.SERVER_HELLO, 7]) {
        await rejectsWith(sealMessage(keys, index, utf8Encode('x')), 'INTERNAL');
        await rejectsWith(openMessage(keys, index, { iv: new Uint8Array(12), ct: new Uint8Array(16) }), 'INTERNAL');
      }
    });

    it('rejects a session key of the wrong length', async () => {
      await rejectsWith(deriveDirectionalKeys(new Uint8Array(16)), 'INTERNAL');
    });

    it('error messages carry only the code', async () => {
      const keys = await deriveDirectionalKeys(generateSessionKey());
      const box = await sealMessage(keys, MESSAGE_INDEX.PASSWORD, utf8Encode('hunter2 hunter2'));
      const err = await openMessage(keys, MESSAGE_INDEX.CHALLENGE, box).catch((e: unknown) => e as Error);
      expect(JSON.stringify(err)).toBe('{"code":"DECRYPTION_FAILED"}');
      expect(String(err)).not.toContain('hunter2');
    });
  });
});
