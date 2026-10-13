import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { z } from 'zod';
interface CredentialStore {
  user: {
    findUnique(args: {
      where: { username: string };
      include: { passwordCredential: true };
    }): Promise<{ id: string; passwordCredential: { hash: string } | null } | null>;
  };
}
const credentials = z
  .object({ username: z.string().min(1).max(128), password: z.string().min(1).max(1024) })
  .strict();
export async function authenticatePassword(
  store: CredentialStore,
  username: string,
  password: string,
  verify: (hash: string, candidate: string) => Promise<boolean>,
) {
  const parsed = credentials.safeParse({ username, password });
  if (!parsed.success) throw new Error('CREDENTIAL_INPUT_INVALID');
  const user = await store.user.findUnique({
    where: { username: parsed.data.username },
    include: { passwordCredential: true },
  });
  if (
    !user?.passwordCredential ||
    !(await verify(user.passwordCredential.hash, parsed.data.password))
  )
    return null;
  return { id: user.id };
}
export function protectIdentifier(value: string, keyHex: string, purpose: string): Buffer {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('IDENTIFIER_KEY_INVALID');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(purpose));
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}
export function revealIdentifier(value: Uint8Array, keyHex: string, purpose: string): string {
  try {
    const bytes = Buffer.from(value);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      Buffer.from(keyHex, 'hex'),
      bytes.subarray(0, 12),
    );
    decipher.setAAD(Buffer.from(purpose));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('IDENTIFIER_UNAVAILABLE');
  }
}
interface PublicAuthenticatorInput {
  id: string;
  type: string;
  nickname: string;
  lastUsedAt: Date | null;
  addressHint: string | null;
}
export function publicAuthenticator(record: PublicAuthenticatorInput) {
  return {
    id: record.id,
    type: record.type,
    nickname: record.nickname,
    lastUsedAt: record.lastUsedAt,
    addressHint: record.addressHint,
  };
}
const authenticatorInput = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('fido2'),
      nickname: z.string().min(1).max(128),
      credentialId: z.string().min(1).max(2048),
      publicKey: z.instanceof(Uint8Array).refine((v) => v.length > 0),
    })
    .strict(),
  z
    .object({
      type: z.literal('voice'),
      nickname: z.string().min(1).max(128),
      channelAddress: z.string().regex(/^\+[1-9][0-9]{7,14}$/),
    })
    .strict(),
  z
    .object({
      type: z.literal('haptic'),
      nickname: z.string().min(1).max(128),
      channelAddress: z.string().min(16).max(256),
      publicKey: z.instanceof(Uint8Array).refine((v) => v.length > 0),
    })
    .strict(),
]);
export function prepareAuthenticatorData(input: unknown, keyHex: string) {
  const parsed = authenticatorInput.safeParse(input);
  if (!parsed.success) throw new Error('AUTHENTICATOR_INPUT_INVALID');
  const data = parsed.data;
  const base = { type: data.type, nickname: data.nickname };
  if (data.type === 'fido2') {
    return {
      ...base,
      publicKey: Buffer.from(data.publicKey),
      credentialIdEncrypted: protectIdentifier(data.credentialId, keyHex, 'fido2'),
      credentialIdDigest: createHmac('sha256', Buffer.from(keyHex, 'hex'))
        .update(data.credentialId)
        .digest('hex'),
      addressHint: '••••',
      channelAddressEncrypted: null,
    };
  }
  return {
    ...base,
    channelAddressEncrypted: protectIdentifier(data.channelAddress, keyHex, data.type),
    addressHint: data.type === 'voice' ? `••••${data.channelAddress.slice(-4)}` : '••••',
    publicKey: data.type === 'haptic' ? Buffer.from(data.publicKey) : null,
    credentialIdEncrypted: null,
    credentialIdDigest: null,
  };
}
