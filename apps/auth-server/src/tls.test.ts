// [RMR] An untrusted certificate is rejected, with verification left ON in every case
import * as x509 from '@peculiar/x509';
import { execFileSync, spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_CERT_FILE, TlsConfigError, loadTlsOptions } from './tls.js';

const HOST = 'auth.deltaforce.lk';
const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const DAY = 24 * 60 * 60 * 1000;

interface Ca {
  pem: string;
  name: string;
  key: CryptoKey;
}
interface Leaf {
  certPem: string;
  keyPem: string;
}

const toPem = (der: ArrayBuffer, label: string) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;

async function makeCa(name: string): Promise<Ca> {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    name: `CN=${name}`,
    keys,
    signingAlgorithm: ALG,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + 30 * DAY),
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { pem: cert.toString('pem'), name, key: keys.privateKey };
}

interface LeafOpts {
  dns?: string[];
  notBefore?: Date;
  notAfter?: Date;
}

async function issueLeaf(ca: Ca, opts: LeafOpts = {}): Promise<Leaf> {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    subject: 'CN=leaf',
    issuer: `CN=${ca.name}`,
    publicKey: keys.publicKey,
    signingKey: ca.key,
    signingAlgorithm: ALG,
    notBefore: opts.notBefore ?? new Date(Date.now() - DAY),
    notAfter: opts.notAfter ?? new Date(Date.now() + 7 * DAY),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension((opts.dns ?? [HOST]).map((value) => ({ type: 'dns' as const, value }))),
    ],
  });
  const keyPem = toPem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY');
  return { certPem: cert.toString('pem'), keyPem };
}

async function selfSignedLeaf(): Promise<Leaf> {
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    name: 'CN=self-signed',
    keys,
    signingAlgorithm: ALG,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: HOST }])],
  });
  return { certPem: cert.toString('pem'), keyPem: toPem(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY') };
}

const servers: Server[] = [];
afterEach(() => {
  while (servers.length) servers.pop()!.close();
});

function listen(tlsOptions: { cert: string | Buffer; key: string | Buffer; minVersion?: 'TLSv1.3' }): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer(tlsOptions, (_req, res) => res.end('ok'));
    servers.push(server);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

type Outcome = { ok: true; protocol: string | null } | { ok: false; code: string };

// Verification is on by default and we never turn it off. Only the trust anchors change.
function dial(port: number, opts: { ca?: string; servername?: string; maxVersion?: 'TLSv1.2' } = {}): Promise<Outcome> {
  return new Promise((resolve) => {
    const socket = connect({
      host: '127.0.0.1',
      port,
      servername: opts.servername ?? HOST,
      ...(opts.ca ? { ca: [opts.ca] } : {}),
      ...(opts.maxVersion ? { maxVersion: opts.maxVersion } : {}),
    });
    socket.once('secureConnect', () => {
      const result: Outcome = socket.authorized ? { ok: true, protocol: socket.getProtocol() } : { ok: false, code: String(socket.authorizationError) };
      socket.destroy();
      resolve(result);
    });
    socket.once('error', (e: NodeJS.ErrnoException) => resolve({ ok: false, code: e.code ?? e.message }));
  });
}

describe('client validates the certificate chain', () => {
  it('control: a leaf from the trusted CA for the right host is accepted', async () => {
    const ca = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(ca);
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    expect(await dial(port, { ca: ca.pem })).toMatchObject({ ok: true });
  });

  it('rejects a leaf issued by an untrusted CA', async () => {
    const trusted = await makeCa('DeltaForce Test CA');
    const rogue = await makeCa('Rogue CA');
    const leaf = await issueLeaf(rogue);
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    expect(await dial(port, { ca: trusted.pem })).toEqual({ ok: false, code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
  });

  it('rejects a rogue CA that copies the trusted CA name', async () => {
    const trusted = await makeCa('DeltaForce Test CA');
    const impostor = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(impostor);
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    const res = await dial(port, { ca: trusted.pem });
    expect(res.ok).toBe(false);
  });

  it('rejects a self-signed leaf', async () => {
    const trusted = await makeCa('DeltaForce Test CA');
    const leaf = await selfSignedLeaf();
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    expect(await dial(port, { ca: trusted.pem })).toEqual({ ok: false, code: 'DEPTH_ZERO_SELF_SIGNED_CERT' });
  });

  it('rejects a trusted CA leaf for the wrong hostname', async () => {
    const ca = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(ca, { dns: ['other.example.lk'] });
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    expect(await dial(port, { ca: ca.pem })).toEqual({ ok: false, code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  });

  it('rejects an expired leaf', async () => {
    const ca = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(ca, { notBefore: new Date(Date.now() - 10 * DAY), notAfter: new Date(Date.now() - DAY) });
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    expect(await dial(port, { ca: ca.pem })).toEqual({ ok: false, code: 'CERT_HAS_EXPIRED' });
  });

  it('does not trust a dev CA unless it is given one', async () => {
    const ca = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(ca);
    const port = await listen({ cert: leaf.certPem, key: leaf.keyPem });
    const res = await dial(port); // default trust store
    expect(res.ok).toBe(false);
  });
});

describe('loadTlsOptions', () => {
  it('reads the files and pins TLS 1.3', async () => {
    const ca = await makeCa('DeltaForce Test CA');
    const leaf = await issueLeaf(ca);
    const dir = mkdtempSync(join(tmpdir(), 'tls-'));
    writeFileSync(join(dir, 'c.pem'), leaf.certPem);
    writeFileSync(join(dir, 'k.pem'), leaf.keyPem);

    const opts = loadTlsOptions({ certFile: join(dir, 'c.pem'), keyFile: join(dir, 'k.pem') });
    expect(opts.minVersion).toBe('TLSv1.3');

    const port = await listen(opts);
    expect(await dial(port, { ca: ca.pem })).toEqual({ ok: true, protocol: 'TLSv1.3' });
    expect((await dial(port, { ca: ca.pem, maxVersion: 'TLSv1.2' })).ok).toBe(false);
  });

  it('throws a named error that points at the docs, without file contents', () => {
    let err: unknown;
    try {
      loadTlsOptions({ certFile: '/nope/cert.pem', keyFile: '/nope/key.pem' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TlsConfigError);
    expect((err as Error).message).toContain('/nope/cert.pem');
    expect((err as Error).message).toContain('docs/dev-certificates.md');
  });
});

describe('TLS verification is never switched off in the repo', () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const banned: [string, RegExp][] = [
    ['rejectUnauthorized: false', /rejectUnauthorized\s*[:=]\s*false/],
    ['NODE_TLS_REJECT_UNAUTHORIZED', /NODE_TLS_REJECT_UNAUTHORIZED/],
    ['strictSSL: false', /strictSSL\s*[:=]\s*false/],
    ['ignoreHTTPSErrors: true', /ignoreHTTPSErrors\s*[:=]\s*true/],
    ['--ignore-certificate-errors', /--ignore-certificate-errors/],
    ['empty checkServerIdentity', /checkServerIdentity\s*[:=]\s*\(\s*\)\s*=>/],
    ['curl -k / --insecure', /\bcurl\b[^\n]*\s(-k|--insecure)\b/],
  ];

  it('finds none of the usual bypasses in tracked or new files', () => {
    const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
      .split('\n')
      .filter((f) => /\.(ts|tsx|js|mjs|cjs|json|ya?ml|sh)$/.test(f) && f !== 'apps/auth-server/src/tls.test.ts' && existsSync(join(root, f)));
    expect(files.length).toBeGreaterThan(5);

    const hits: string[] = [];
    for (const f of files) {
      const text = readFileSync(join(root, f), 'utf8');
      for (const [label, re] of banned) if (re.test(text)) hits.push(`${f}: ${label}`);
    }
    expect(hits).toEqual([]);
  });
});

// Only runs on a machine that has run scripts/dev-certs.mts
const caRoot = spawnSync('mkcert', ['-CAROOT'], { encoding: 'utf8' });
const rootFile = caRoot.status === 0 ? join(caRoot.stdout.trim(), 'rootCA.pem') : '';
const haveRealCert = existsSync(DEFAULT_CERT_FILE) && existsSync(rootFile);

describe('the real mkcert certificate', () => {
  it.skipIf(!haveRealCert)('is for auth.deltaforce.lk and chains to this machine\'s mkcert root', () => {
    const leaf = new X509Certificate(readFileSync(DEFAULT_CERT_FILE));
    const root = new X509Certificate(readFileSync(rootFile));
    expect(leaf.checkHost(HOST)).toBe(HOST);
    expect(leaf.checkIssued(root)).toBe(true);
    expect(leaf.verify(root.publicKey)).toBe(true);
    expect(new Date(leaf.validTo).getTime()).toBeGreaterThan(Date.now());
  });
});
