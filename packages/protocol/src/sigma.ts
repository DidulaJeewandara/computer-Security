// [RMR] sigma_s: ECDSA P-256 over the canonical encoding of nonce_u, PKEncKey_u and S_id. Shared by signer and verifier.
import { utf8Encode } from './bytes.js';
import { NOTATION } from './constants.js';
import { decodeSigmaSPayload, encodeSigmaSPayload, type SigmaSPayload } from './encode.js';

const ECDSA = { name: 'ECDSA', hash: 'SHA-256' } as const;

// WebCrypto wants ArrayBuffer-backed arrays.
const bs = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

/** HPKE info for c1, used by the server to seal and by the client to open. */
export const C1_INFO = utf8Encode('deltaforce/v1 c1');

/** `signed` is the exact bytes under the signature; it is sent along so each client check can fail on its own. */
export async function signSigmaS(
  privateKey: CryptoKey,
  payload: SigmaSPayload,
): Promise<{ sigmaS: Uint8Array; signed: Uint8Array }> {
  const signed = encodeSigmaSPayload(payload); // all three fields, validated first
  const sigmaS = new Uint8Array(await globalThis.crypto.subtle.sign(ECDSA, privateKey, bs(signed)));
  return { sigmaS, signed };
}

/** False on anything wrong, including a `signed` that is not exactly three well-formed fields. */
export async function verifySigmaS(publicKey: CryptoKey, signed: Uint8Array, sigmaS: Uint8Array): Promise<boolean> {
  try {
    if (sigmaS.length !== NOTATION.SIGMA_S_BYTES) return false;
    decodeSigmaSPayload(signed);
    return await globalThis.crypto.subtle.verify(ECDSA, publicKey, bs(sigmaS), bs(signed));
  } catch {
    return false;
  }
}
