import { describe, expect, it, vi } from 'vitest';
import {
  authenticatePassword,
  publicAuthenticator,
  protectIdentifier,
  revealIdentifier,
  prepareAuthenticatorData,
} from '../../../apps/auth-server/src/db/userService.js';

describe('P1-UDK-1 database service boundary', () => {
  it('verifies a stored hash through the injected password verifier', async () => {
    const verify = vi.fn().mockResolvedValue(true);
    const store = {
      user: {
        findUnique: vi
          .fn()
          .mockResolvedValue({ id: 'user-1', passwordCredential: { hash: 'encoded-argon2id' } }),
      },
    };
    expect(await authenticatePassword(store, 'demo', 'candidate', verify)).toEqual({
      id: 'user-1',
    });
    expect(verify).toHaveBeenCalledWith('encoded-argon2id', 'candidate');
  });
  it('refuses unknown accounts and wrong passwords with no sensitive response', async () => {
    const store = { user: { findUnique: vi.fn().mockResolvedValue(null) } };
    expect(await authenticatePassword(store, 'unknown', 'candidate', vi.fn())).toBeNull();
    store.user.findUnique.mockResolvedValue({ id: 'user-1', passwordCredential: { hash: 'hash' } });
    expect(
      await authenticatePassword(store, 'demo', 'candidate', vi.fn().mockResolvedValue(false)),
    ).toBeNull();
  });
  it('validates inputs before touching storage', async () => {
    const lookup = vi.fn();
    await expect(
      authenticatePassword({ user: { findUnique: lookup } }, '', 'candidate', vi.fn()),
    ).rejects.toThrow('CREDENTIAL_INPUT_INVALID');
    expect(lookup).not.toHaveBeenCalled();
  });
  it('encrypts sensitive identifiers with randomized authenticated encryption', () => {
    const key = 'ab'.repeat(32);
    const first = protectIdentifier('+94771234567', key, 'voice');
    const second = protectIdentifier('+94771234567', key, 'voice');
    expect(first).not.toEqual(second);
    expect(first.toString()).not.toContain('+94771234567');
    expect(revealIdentifier(first, key, 'voice')).toBe('+94771234567');
    expect(() => revealIdentifier(first, 'cd'.repeat(32), 'voice')).toThrow(
      'IDENTIFIER_UNAVAILABLE',
    );
    expect(() => revealIdentifier(first, key, 'fido2')).toThrow('IDENTIFIER_UNAVAILABLE');
  });
  it('stores phone addresses and credential IDs as ciphertext with masked hints', () => {
    const key = 'ab'.repeat(32);
    const phone = prepareAuthenticatorData(
      { type: 'voice', nickname: 'My phone', channelAddress: '+94771234567' },
      key,
    );
    expect(phone.addressHint).toBe('••••4567');
    expect(phone.channelAddressEncrypted?.toString()).not.toContain('+94771234567');
    const device = prepareAuthenticatorData(
      {
        type: 'fido2',
        nickname: 'My key',
        credentialId: 'credential-id-abcdef',
        publicKey: new Uint8Array([1, 2]),
      },
      key,
    );
    expect(device.credentialIdDigest).toHaveLength(64);
    expect(device.credentialIdEncrypted?.toString()).not.toContain('credential-id-abcdef');
    expect(() =>
      prepareAuthenticatorData({ type: 'voice', nickname: 'Bad', channelAddress: 'invalid' }, key),
    ).toThrow('AUTHENTICATOR_INPUT_INVALID');
  });
  it('public presentation includes only safe fields and masked hints', () => {
    const record = {
      id: 'factor-1',
      type: 'voice',
      nickname: 'My phone',
      lastUsedAt: null,
      addressHint: '••••4567',
      channelAddressEncrypted: Buffer.from('private'),
      credentialIdEncrypted: Buffer.from('private-key-id'),
      publicKey: Buffer.from('public-key'),
    };
    expect(publicAuthenticator(record)).toEqual({
      id: 'factor-1',
      type: 'voice',
      nickname: 'My phone',
      lastUsedAt: null,
      addressHint: '••••4567',
    });
  });
});
