// [JDH] P3-JDH-1: FIDO2 suite on the Chromium virtual authenticator — runs headless, no hardware
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, test, type Page } from '@playwright/test';
import { addVirtualAuthenticator } from '../../packages/testkit/src/virtualAuthenticator.js';

// A blank page on http://localhost is a secure context, which WebAuthn requires. The fixture
// self-tests use RP ID "localhost"; the real suite below runs against S_id on the auth server.
let server: Server;
let origin: string;

test.beforeAll(async () => {
  server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><title>webauthn fixture</title>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://localhost:${(server.address() as AddressInfo).port}`;
});

test.afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

/** Registers a credential in the page and returns its id, as the browser reports it. */
function register(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const cred = (await navigator.credentials.create({
      publicKey: {
        rp: { id: 'localhost', name: 'fixture' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'alice',
          displayName: 'Alice',
        },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        attestation: 'none',
      },
    })) as PublicKeyCredential;
    return cred.id;
  });
}

/** Runs one assertion and returns the signature counter from authenticatorData. */
function authenticate(page: Page, credentialId: string): Promise<number> {
  return page.evaluate(async (id) => {
    const fromB64Url = (s: string) =>
      Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    const cred = (await navigator.credentials.get({
      publicKey: {
        rpId: 'localhost',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: fromB64Url(id) }],
        userVerification: 'preferred',
      },
    })) as PublicKeyCredential;
    const data = new DataView((cred.response as AuthenticatorAssertionResponse).authenticatorData);
    return data.getUint32(33); // rpIdHash (32) + flags (1), then the big-endian counter
  }, credentialId);
}

test.describe('virtual authenticator fixture', () => {
  test('registers and authenticates with no hardware attached', async ({ page }) => {
    const auth = await addVirtualAuthenticator(page);
    await page.goto(origin);
    const id = await register(page);
    const [enrolled] = await auth.credentials();
    expect(enrolled).toBeDefined();
    // The counter goes up by one per ceremony (Chromium counts the registration too).
    const start = enrolled!.signCount;
    expect(await authenticate(page, id)).toBe(start + 1);
    expect(await authenticate(page, id)).toBe(start + 2);
    await auth.remove();
  });

  test('can model a cloned key: a copy of the credential with an older counter', async ({
    page,
  }) => {
    const original = await addVirtualAuthenticator(page);
    await page.goto(origin);
    const id = await register(page);
    const snapshotCount = (await original.credentials())[0]!.signCount;
    for (let i = 0; i < 3; i++) await authenticate(page, id);
    const [cred] = await original.credentials();
    expect(cred!.signCount).toBe(snapshotCount + 3);
    await original.remove();

    // The clone starts from a snapshot taken right after enrolment.
    const clone = await addVirtualAuthenticator(page);
    await clone.addCredential({ ...cred!, signCount: snapshotCount });
    // The browser happily signs; spotting counter regression is the server's job (P3-RMR-2).
    // so its next counter is lower than one the server has already seen
    expect(await authenticate(page, id)).toBe(snapshotCount + 1);
    expect(snapshotCount + 1).toBeLessThan(cred!.signCount);
    await clone.remove();
  });

  test('can withhold user presence so the timeout path can be tested', async ({ page }) => {
    const auth = await addVirtualAuthenticator(page, { automaticPresenceSimulation: false });
    await page.goto(origin);
    const outcome = await page.evaluate(async () => {
      try {
        await navigator.credentials.create({
          publicKey: {
            rp: { id: 'localhost', name: 'fixture' },
            user: { id: new Uint8Array(16), name: 'alice', displayName: 'Alice' },
            challenge: new Uint8Array(32),
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 1000,
          },
        });
        return 'created';
      } catch (e) {
        return (e as DOMException).name;
      }
    });
    expect(outcome).toBe('NotAllowedError');
    await auth.remove();
  });
});

// The four acceptance cases of P3-JDH-1. They need the WebAuthn server routes (P3-RMR-1
// registration, P3-RMR-2 assertion as step 5a) and the web flow driving them. Each is
// marked fixme until those land, so CI reports them instead of silently passing.
test.describe('FIDO2 suite against the auth server', () => {
  test.fixme('happy path: enrol a key, then log in with it as step 5a', async () => {});
  test.fixme('an assertion made for the wrong RP ID is refused', async () => {});
  test.fixme('a cloned key is detected by signature-counter regression', async () => {});
  test.fixme('a replayed assertion is refused', async () => {});
});
