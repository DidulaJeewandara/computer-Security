// [JDH] P3-JDH-1: Chromium virtual authenticator over CDP, so FIDO2 tests run headless with no hardware
import type { CDPSession, Page } from '@playwright/test';

export interface VirtualAuthenticatorOptions {
  /** ctap2 is a modern security key or platform authenticator. */
  protocol?: 'ctap2' | 'u2f';
  transport?: 'usb' | 'nfc' | 'ble' | 'internal';
  hasResidentKey?: boolean;
  hasUserVerification?: boolean;
  isUserVerified?: boolean;
  /** Answer "touch the key" automatically; turn off to test the timeout path. */
  automaticPresenceSimulation?: boolean;
}

/** A credential as the authenticator holds it. `privateKey` is base64 PKCS#8. */
export interface VirtualCredential {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string;
  userHandle?: string;
  signCount: number;
}

export interface VirtualAuthenticator {
  readonly id: string;
  credentials(): Promise<VirtualCredential[]>;
  /** Put a credential on this authenticator, e.g. a copy of another one's, to model a cloned key. */
  addCredential(credential: VirtualCredential): Promise<void>;
  clearCredentials(): Promise<void>;
  /** Whether the next ceremony sees a user who touched the key and passed verification. */
  setUserVerified(verified: boolean): Promise<void>;
  remove(): Promise<void>;
}

const DEFAULTS: Required<VirtualAuthenticatorOptions> = {
  protocol: 'ctap2',
  transport: 'usb',
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};

/** Attaches a virtual authenticator to this page's browser context. Chromium only. */
export async function addVirtualAuthenticator(
  page: Page,
  options: VirtualAuthenticatorOptions = {},
): Promise<VirtualAuthenticator> {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...DEFAULTS, ...options },
  });
  return {
    id: authenticatorId,
    async credentials() {
      const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials as VirtualCredential[];
    },
    async addCredential(credential) {
      await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
    },
    async clearCredentials() {
      await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
    },
    async setUserVerified(isUserVerified) {
      await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified });
    },
    async remove() {
      await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      await cdp.detach();
    },
  };
}
