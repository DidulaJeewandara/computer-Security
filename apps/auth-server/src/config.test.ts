import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './config.js';

export const validEnv = {
  DATABASE_URL: 'postgresql://deltaforce:local-password@localhost:5432/deltaforce',
  REDIS_URL: 'redis://localhost:6379',
  WEB_ORIGIN: 'https://localhost:5173',
  TLS_CERT_FILE: 'keys/auth.deltaforce.lk.pem',
  TLS_KEY_FILE: 'keys/auth.deltaforce.lk-key.pem',
  DATA_ENCRYPTION_KEY: 'ab'.repeat(32),
};

describe('P0-UDK-2 configuration boundary', () => {
  it('parses valid configuration and defaults', () => {
    expect(loadConfig(validEnv)).toMatchObject({
      port: 8443,
      host: '127.0.0.1',
      webOrigin: validEnv.WEB_ORIGIN,
    });
  });
  it('resolves TLS paths from the repository root independent of the server working directory', () => {
    expect(loadConfig(validEnv).tlsCertFile).toBe(resolve('keys/auth.deltaforce.lk.pem'));
    expect(loadConfig(validEnv).tlsKeyFile).toBe(resolve('keys/auth.deltaforce.lk-key.pem'));
  });
  for (const field of Object.keys(validEnv)) {
    it(`names missing ${field} without revealing other values`, () => {
      const env: Record<string, string> = { ...validEnv };
      delete env[field];
      expect(() => loadConfig(env)).toThrow(ConfigError);
      try {
        loadConfig(env);
      } catch (error) {
        expect((error as Error).message).toContain(field);
        expect((error as Error).message).not.toContain('local-password');
      }
    });
  }
  for (const [field, value] of [
    ['DATABASE_URL', 'https://example.com'],
    ['REDIS_URL', 'http://example.com'],
    ['WEB_ORIGIN', 'http://localhost:5173'],
    ['WEB_ORIGIN', 'not-a-url'],
    ['WEB_ORIGIN', 'https://example.com/path'],
    ['PORT', '0'],
    ['PORT', '65536'],
    ['DATA_ENCRYPTION_KEY', 'bad'],
    ['TLS_KEY_FILE', ''],
  ]) {
    it(`rejects malformed ${field}: ${value}`, () => {
      expect(() => loadConfig({ ...validEnv, [field!]: value })).toThrow(field);
    });
  }
  it('documents every configuration field', () => {
    const example = readFileSync('.env.example', 'utf8');
    for (const field of [
      ...Object.keys(validEnv),
      'HOST',
      'PORT',
      'NODE_ENV',
      'SEED_USERNAME',
      'SEED_PASSWORD',
    ]) {
      expect(example).toContain(`${field}=`);
    }
  });
  it('no other application file reads the environment directly', () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)],
      );
    for (const file of [...walk('apps'), ...walk('packages'), ...walk('scripts')].filter(
      (f) =>
        /\.(ts|tsx|mts)$/.test(f) &&
        !f.includes('/dist/') &&
        !f.includes('/node_modules/') &&
        !f.endsWith('.test.ts') &&
        !f.endsWith('/config.ts'),
    )) {
      expect(readFileSync(file, 'utf8'), file).not.toMatch(
        /process\s*(?:\.\s*env|\[\s*['"]env['"]\s*\])/,
      );
    }
  });
});
