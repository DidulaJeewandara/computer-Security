// [RMR] 32-byte CSPRNG nonces, X25519, HPKE seal/open, AES-256-GCM with a subkey per direction and message index as AAD
import { fromBase64Url, utf8Encode } from './bytes.js';
import { MESSAGE_INDEX, NOTATION } from './constants.js';
import { ProtocolError } from './errors.js';
import type { AeadBox, HpkeBox } from './types.js';

// WebCrypto only: same API in Node and the browser, no Buffer.
const subtle = globalThis.crypto.subtle;

const NH = 32; // SHA-256 output
const X25519_PKCS8_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);

// Typed arrays are ArrayBufferLike by default, but WebCrypto wants ArrayBuffer-backed ones.
const bs = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const u16be = (n: number) => Uint8Array.of((n >> 8) & 255, n & 255);
const u32be = (n: number) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const allZero = (b: Uint8Array) => b.every((x) => x === 0);

// ---- randomness ---------------------------------------------------------------

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** nonce_u, nonce_s, nonce_s2: 32 CSPRNG bytes, never a timestamp. */
export const randomNonce = (): Uint8Array<ArrayBuffer> => randomBytes(NOTATION.NONCE_BYTES);

/** `key` inside c1, the root of both directional Enc_key subkeys. */
export const generateSessionKey = (): Uint8Array<ArrayBuffer> => randomBytes(NOTATION.AES_GCM.KEY_BYTES);

// ---- X25519 -------------------------------------------------------------------

export interface EncKeyPair {
  /** Not extractable. */
  privateKey: CryptoKey;
  /** Raw 32-byte X25519 public key, this is PKEncKey_u. */
  publicKey: Uint8Array;
}

/** Ephemeral pair for one login. */
export async function generateEncKeyPair(): Promise<EncKeyPair> {
  const pair = (await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await subtle.exportKey('raw', pair.publicKey)) };
}

// ---- HPKE (RFC 9180), base mode, single shot, our one suite -------------------

const KEM_SUITE = concat(utf8Encode('KEM'), u16be(NOTATION.HPKE.KEM_ID));
const HPKE_SUITE = concat(
  utf8Encode('HPKE'),
  u16be(NOTATION.HPKE.KEM_ID),
  u16be(NOTATION.HPKE.KDF_ID),
  u16be(NOTATION.HPKE.AEAD_ID),
);
const V1 = utf8Encode('HPKE-v1');

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const k = await subtle.importKey('raw', bs(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, bs(data)));
}

// HMAC pads a short key with zeros, so an empty salt is NH zero bytes.
const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
  hmac(salt.length ? salt : new Uint8Array(NH), concat(V1, suite, utf8Encode(label), ikm));

async function labeledExpand(suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, len: number) {
  const labeledInfo = concat(u16be(len), V1, suite, utf8Encode(label), info);
  const out = new Uint8Array(len);
  let t: Uint8Array = new Uint8Array(0);
  for (let i = 1, o = 0; o < len; i++, o += NH) {
    t = await hmac(prk, concat(t, labeledInfo, Uint8Array.of(i)));
    out.set(t.subarray(0, Math.min(NH, len - o)), o);
  }
  return out;
}

const none = new Uint8Array(0);

// RFC 9180 DeriveKeyPair. Needed for the known-answer tests.
export async function deriveEncKeyPair(ikm: Uint8Array): Promise<EncKeyPair> {
  const prk = await labeledExtract(KEM_SUITE, none, 'dkp_prk', ikm);
  const sk = await labeledExpand(KEM_SUITE, prk, 'sk', none, 32);
  const pkcs8 = concat(X25519_PKCS8_PREFIX, sk);
  const tmp = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
  const x = (await subtle.exportKey('jwk', tmp)).x;
  const publicKey = fromBase64Url(x ?? '');
  if (publicKey?.length !== NOTATION.X25519_PUBLIC_KEY_BYTES) throw new ProtocolError('INTERNAL');
  const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
  return { privateKey, publicKey };
}

async function dh(privateKey: CryptoKey, publicKey: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (publicKey.length !== NOTATION.X25519_PUBLIC_KEY_BYTES) throw new Error('bad public key length');
  const pub = await subtle.importKey('raw', bs(publicKey), { name: 'X25519' }, false, []);
  const out = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, privateKey, 256));
  if (allZero(out)) throw new Error('low-order point'); // RFC 9180 section 7.1.4
  return out;
}

async function sharedSecret(dhOut: Uint8Array, enc: Uint8Array, pkR: Uint8Array) {
  const eaePrk = await labeledExtract(KEM_SUITE, none, 'eae_prk', dhOut);
  return labeledExpand(KEM_SUITE, eaePrk, 'shared_secret', concat(enc, pkR), 32);
}

async function keySchedule(secretFromKem: Uint8Array, info: Uint8Array) {
  const pskIdHash = await labeledExtract(HPKE_SUITE, none, 'psk_id_hash', none);
  const infoHash = await labeledExtract(HPKE_SUITE, none, 'info_hash', info);
  const context = concat(Uint8Array.of(0), pskIdHash, infoHash); // mode 0 = base
  const secret = await labeledExtract(HPKE_SUITE, secretFromKem, 'secret', none);
  const key = await labeledExpand(HPKE_SUITE, secret, 'key', context, NOTATION.AES_GCM.KEY_BYTES);
  const baseNonce = await labeledExpand(HPKE_SUITE, secret, 'base_nonce', context, NOTATION.AES_GCM.IV_BYTES);
  return { key: await subtle.importKey('raw', bs(key), 'AES-GCM', false, ['encrypt', 'decrypt']), baseNonce };
}

/** Only for the known-answer tests, which need a fixed ephemeral key. Not in the barrel. */
export async function sealWithEphemeral(
  pkR: Uint8Array,
  ephemeral: EncKeyPair,
  info: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
): Promise<HpkeBox> {
  let secret: Uint8Array;
  try {
    secret = await sharedSecret(await dh(ephemeral.privateKey, pkR), ephemeral.publicKey, pkR);
  } catch {
    throw new ProtocolError('MALFORMED_MESSAGE');
  }
  const { key, baseNonce } = await keySchedule(secret, info);
  // One message per context, so the sequence number is 0 and the nonce is base_nonce.
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: bs(baseNonce), additionalData: bs(aad) }, key, bs(pt));
  return { enc: ephemeral.publicKey, ct: new Uint8Array(ct) };
}

/** PKEnc: seal to the recipient's X25519 public key. */
export async function hpkeSeal(pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<HpkeBox> {
  return sealWithEphemeral(pkR, await generateEncKeyPair(), info, aad, pt);
}

/** Any failure is DECRYPTION_FAILED, whatever the cause. */
export async function hpkeOpen(
  recipient: EncKeyPair,
  info: Uint8Array,
  aad: Uint8Array,
  box: HpkeBox,
): Promise<Uint8Array> {
  try {
    const secret = await sharedSecret(await dh(recipient.privateKey, box.enc), box.enc, recipient.publicKey);
    const { key, baseNonce } = await keySchedule(secret, info);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: bs(baseNonce), additionalData: bs(aad) }, key, bs(box.ct));
    return new Uint8Array(pt);
  } catch {
    throw new ProtocolError('DECRYPTION_FAILED');
  }
}

// ---- Enc_key: AES-256-GCM, one subkey per direction ---------------------------

export interface DirectionalKeys {
  clientToServer: CryptoKey;
  serverToClient: CryptoKey;
}

const LABEL_C2S = utf8Encode('deltaforce/v1 enc_key client-to-server');
const LABEL_S2C = utf8Encode('deltaforce/v1 enc_key server-to-client');

/** HKDF-SHA256 over the session key. Salt is empty because the key is already uniform random. */
export async function deriveDirectionalKeys(key: Uint8Array): Promise<DirectionalKeys> {
  if (key.length !== NOTATION.AES_GCM.KEY_BYTES) throw new ProtocolError('INTERNAL');
  const base = await subtle.importKey('raw', bs(key), 'HKDF', false, ['deriveKey']);
  const derive = (info: Uint8Array) =>
    subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: bs(info) },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  return { clientToServer: await derive(LABEL_C2S), serverToClient: await derive(LABEL_S2C) };
}

// The message number picks the key, so a caller can't seal in the wrong direction.
function keyFor(keys: DirectionalKeys, index: number): CryptoKey {
  switch (index) {
    case MESSAGE_INDEX.PASSWORD:
    case MESSAGE_INDEX.RESPONSE:
      return keys.clientToServer;
    case MESSAGE_INDEX.CHALLENGE:
    case MESSAGE_INDEX.RESULT:
      return keys.serverToClient;
    default:
      throw new ProtocolError('INTERNAL'); // messages 1 and 2 are not under Enc_key
  }
}

/** Random 12-byte IV per message: step 5 can be retried under the same key and index. */
export async function sealMessage(keys: DirectionalKeys, index: number, pt: Uint8Array): Promise<AeadBox> {
  const key = keyFor(keys, index);
  const iv = randomBytes(NOTATION.AES_GCM.IV_BYTES);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: u32be(index) }, key, bs(pt));
  return { iv, ct: new Uint8Array(ct) };
}

export async function openMessage(keys: DirectionalKeys, index: number, box: AeadBox): Promise<Uint8Array> {
  const key = keyFor(keys, index);
  if (box.iv.length !== NOTATION.AES_GCM.IV_BYTES || box.ct.length < NOTATION.AES_GCM.TAG_BYTES) {
    throw new ProtocolError('DECRYPTION_FAILED');
  }
  try {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: bs(box.iv), additionalData: u32be(index) }, key, bs(box.ct));
    return new Uint8Array(pt);
  } catch {
    throw new ProtocolError('DECRYPTION_FAILED');
  }
}
