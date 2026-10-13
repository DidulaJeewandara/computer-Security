import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { get as httpsGet } from 'node:https';
import { get as httpGet } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
let directory: string;
let config: ReturnType<typeof loadConfig>;
beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), 'udk-tls-'));
  const cert = join(directory, 'cert.pem');
  const key = join(directory, 'key.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      key,
      '-out',
      cert,
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  );
  config = loadConfig({
    DATABASE_URL: 'postgresql://localhost/test',
    REDIS_URL: 'redis://localhost',
    WEB_ORIGIN: 'https://localhost:5173',
    TLS_CERT_FILE: cert,
    TLS_KEY_FILE: key,
    DATA_ENCRYPTION_KEY: 'ab'.repeat(32),
  });
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
describe('P1-UDK-2 hardened HTTPS server', () => {
  it('sets HSTS, strict CSP and independent request IDs', async () => {
    const app = await buildApp(config);
    try {
      const first = await app.inject({
        url: '/health',
        headers: { 'x-request-id': 'attacker-controlled' },
      });
      const second = await app.inject('/health');
      expect(first.statusCode).toBe(200);
      expect(first.headers['strict-transport-security']).toContain('includeSubDomains');
      expect(first.headers['content-security-policy']).toContain("default-src 'none'");
      expect(first.headers['content-security-policy']).not.toContain('unsafe-inline');
      expect(first.headers['x-request-id']).toBeTruthy();
      expect(first.headers['x-request-id']).not.toBe('attacker-controlled');
      expect(first.headers['x-request-id']).not.toBe(second.headers['x-request-id']);
    } finally {
      await app.close();
    }
  });
  it('allows only the configured web origin, including preflight', async () => {
    const app = await buildApp(config);
    try {
      const allowed = await app.inject({ url: '/health', headers: { origin: config.webOrigin } });
      expect(allowed.headers['access-control-allow-origin']).toBe(config.webOrigin);
      const denied = await app.inject({
        url: '/health',
        headers: { origin: 'https://evil.example' },
      });
      expect(denied.statusCode).toBe(403);
      expect(denied.headers['access-control-allow-origin']).toBeUndefined();
      const preflight = await app.inject({
        method: 'OPTIONS',
        url: '/health',
        headers: { origin: config.webOrigin, 'access-control-request-method': 'POST' },
      });
      expect(preflight.statusCode).toBe(204);
      expect(preflight.headers['access-control-allow-origin']).toBe(config.webOrigin);
    } finally {
      await app.close();
    }
  });
  it('posts credentials and keeps nested secrets, headers, URL values and errors out of logs', async () => {
    let captured = '';
    const stream = new Writable({
      write(chunk, _encoding, done) {
        captured += chunk.toString();
        done();
      },
    });
    const app = await buildApp(config, { logStream: stream });
    app.post('/redaction-test', async (request) => {
      app.log.info(
        { payload: request.body, nested: [{ Password: 'nested-password', OTP: 'nested-otp' }] },
        'boundary exercised',
      );
      throw new Error('provider-secret-value');
    });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/redaction-test?token=url-token',
        headers: { authorization: 'header-authorization', cookie: 'header-cookie' },
        payload: {
          password: 'posted-password',
          otp: 'posted-otp',
          code: 'posted-code',
          token: 'posted-token',
          secret: 'posted-secret',
          child: { authorization: 'nested-authorization', cookie: 'nested-cookie' },
        },
      });
      expect(response.statusCode).toBe(500);
      for (const secret of [
        'posted-password',
        'posted-otp',
        'posted-code',
        'posted-token',
        'posted-secret',
        'nested-password',
        'nested-otp',
        'header-authorization',
        'header-cookie',
        'nested-authorization',
        'nested-cookie',
        'url-token',
        'provider-secret-value',
      ]) {
        expect(captured).not.toContain(secret);
        expect(response.body).not.toContain(secret);
      }
      expect(captured).toContain('[REDACTED]');
      expect(response.json()).toEqual({
        error: 'REQUEST_FAILED',
        message: 'The request could not be completed. Please try again.',
      });
    } finally {
      await app.close();
    }
  });
  it('listens with trusted TLS and refuses plaintext HTTP', async () => {
    const app = await buildApp(config);
    try {
      await app.listen({ host: '127.0.0.1', port: 0 });
      const address = app.server.address();
      if (!address || typeof address === 'string') throw new Error('Expected TCP address');
      const url = `https://localhost:${address.port}/health`;
      const status = await new Promise<number | undefined>((resolve, reject) => {
        httpsGet(url, { ca: readFileSync(config.tlsCertFile), minVersion: 'TLSv1.3' }, (res) => {
          res.resume();
          resolve(res.statusCode);
        }).on('error', reject);
      });
      expect(status).toBe(200);
      await expect(
        new Promise((resolve, reject) => {
          httpGet(url.replace('https:', 'http:'), (res) => {
            res.resume();
            resolve(res.statusCode);
          }).on('error', reject);
        }),
      ).rejects.toThrow();
    } finally {
      await app.close();
    }
  });
});
