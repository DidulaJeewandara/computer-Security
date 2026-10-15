// [RMR] Fastify plugin: steps 1 and 2 (sigma_s over nonce_u, PKEncKey_u, S_id), 4, 5b and 6
import type { z } from 'zod';
import {
  C1_INFO,
  HelloSchema,
  NOTATION,
  ProtocolError,
  ServerHelloSchema,
  generateSessionKey,
  hpkeSeal,
  randomBytes,
  randomNonce,
  safeIssues,
  signSigmaS,
  toBase64Url,
} from '@deltaforce/protocol';

// TODO(RMR-10, RMR-12): steps 4, 5b and 6, and the Fastify route that calls handleHello.

/** The server's signing key. UDK's serverKey.ts will provide it. */
export interface SigmaSigner {
  keyId: string;
  privateKey: CryptoKey;
}

export interface PendingAuthRecord {
  uId: string;
  nonceU: Uint8Array;
  pkEncKeyU: Uint8Array;
  sessionKey: Uint8Array;
  nonceS: Uint8Array;
  nonceS2: Uint8Array;
  keyId: string;
  state: 'AWAITING_PASSWORD';
  attempts: 0;
  expiresAt: number;
}

/** UDK's pendingAuth.ts will implement this over Redis. */
export interface PendingStore {
  create(id: string, record: PendingAuthRecord, ttlSeconds: number): Promise<void>;
}

export interface HelloDeps {
  signer: SigmaSigner;
  pending: PendingStore;
  now?: () => number;
}

export async function handleHello(wire: unknown, deps: HelloDeps) {
  const parsed = HelloSchema.safeDecode(wire as z.input<typeof HelloSchema>); // zod does the real check
  if (!parsed.success) throw new ProtocolError('MALFORMED_MESSAGE', safeIssues(parsed.error));
  const hello = parsed.data;
  if (hello.sId !== NOTATION.S_ID) throw new ProtocolError('SERVER_ID_MISMATCH');

  const sessionKey = generateSessionKey();
  const nonceS = randomNonce();
  const nonceS2 = randomNonce();

  // All three fields go under the signature; the nonce alone is the Lowe weakness.
  const { sigmaS, signed } = await signSigmaS(deps.signer.privateKey, {
    nonceU: hello.nonceU,
    pkEncKeyU: hello.pkEncKeyU,
    sId: hello.sId,
  });
  // The signed bytes are the AAD, so c1 only opens inside this handshake.
  const c1 = await hpkeSeal(hello.pkEncKeyU, C1_INFO, signed, sessionKey);

  const ttl = NOTATION.PENDING_AUTH.TTL_SECONDS;
  const pendingId = toBase64Url(randomBytes(NOTATION.SESSION_ID_BYTES));
  await deps.pending.create(
    pendingId,
    {
      uId: hello.uId,
      nonceU: hello.nonceU,
      pkEncKeyU: hello.pkEncKeyU,
      sessionKey,
      nonceS,
      nonceS2,
      keyId: deps.signer.keyId,
      state: 'AWAITING_PASSWORD',
      attempts: 0,
      expiresAt: (deps.now ?? Date.now)() + ttl * 1000,
    },
    ttl,
  );

  const message = ServerHelloSchema.encode({ type: 'server_hello', sigmaS, signed, c1, nonceS });
  return { pendingId, message };
}
