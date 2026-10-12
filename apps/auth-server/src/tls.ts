// [RMR] Loads the dev TLS cert for Fastify's https option (UDK-4 wires it in)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const keysDir = fileURLToPath(new URL('../../../keys/', import.meta.url));

export const DEFAULT_CERT_FILE = `${keysDir}auth.deltaforce.lk.pem`;
export const DEFAULT_KEY_FILE = `${keysDir}auth.deltaforce.lk-key.pem`;

export class TlsConfigError extends Error {
  constructor(file: string) {
    // path only, never file contents
    super(`TLS_FILE_MISSING: cannot read ${file}. Run "node scripts/dev-certs.mts", see docs/dev-certificates.md`);
    this.name = 'TlsConfigError';
  }
}

export interface TlsFiles {
  certFile?: string;
  keyFile?: string;
}

export function loadTlsOptions(files: TlsFiles = {}) {
  const read = (file: string) => {
    try {
      return readFileSync(file);
    } catch {
      throw new TlsConfigError(file);
    }
  };
  return {
    cert: read(files.certFile ?? DEFAULT_CERT_FILE),
    key: read(files.keyFile ?? DEFAULT_KEY_FILE),
    minVersion: 'TLSv1.3' as const,
  };
}
