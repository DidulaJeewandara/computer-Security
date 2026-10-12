// [RMR] Dev TLS helper: node scripts/dev-certs.mts [issue|serve] [--san <ip>]...
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST = 'auth.deltaforce.lk';
const PORT = 8443;
const keysDir = fileURLToPath(new URL('../keys/', import.meta.url));
const certFile = join(keysDir, `${HOST}.pem`);
const keyFile = join(keysDir, `${HOST}-key.pem`);

const args = process.argv.slice(2);
const command = args[0]?.startsWith('--') ? 'issue' : (args[0] ?? 'issue');
const rest = args.slice(args[0]?.startsWith('--') ? 0 : 1);
const extraSans = rest.flatMap((a, i) => (a === '--san' && rest[i + 1] ? [rest[i + 1]!] : []));

function die(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function issue() {
  if (spawnSync('mkcert', ['-version']).error) {
    die('mkcert not found. Install it first, see docs/dev-certificates.md');
  }
  mkdirSync(keysDir, { recursive: true });

  // creates the local CA and adds it to the OS and browser trust stores
  if (spawnSync('mkcert', ['-install'], { stdio: 'inherit' }).status !== 0) die('mkcert -install failed');

  const names = [HOST, 'localhost', '127.0.0.1', '::1', ...extraSans];
  const args = ['-cert-file', certFile, '-key-file', keyFile, ...names];
  if (spawnSync('mkcert', args, { stdio: 'inherit' }).status !== 0) die('mkcert could not issue the cert');

  const hostsFile = process.platform === 'win32' ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' : '/etc/hosts';
  const hosts = existsSync(hostsFile) ? readFileSync(hostsFile, 'utf8') : '';
  if (!hosts.split('\n').some((l) => !l.trim().startsWith('#') && l.includes(HOST))) {
    console.warn(`\nMissing hosts entry. Add "127.0.0.1 ${HOST}" to ${hostsFile} (see docs).`);
  }
  console.log(`\nIssued ${certFile}\nNext: node scripts/dev-certs.mts serve`);
}

function serve() {
  if (!existsSync(certFile) || !existsSync(keyFile)) die('No cert yet. Run: node scripts/dev-certs.mts');
  createServer({ cert: readFileSync(certFile), key: readFileSync(keyFile), minVersion: 'TLSv1.3' }, (_req, res) => {
    res.end('ok\n');
  }).listen(PORT, () => console.log(`Open https://${HOST}:${PORT}, there should be no warning`));
}

if (command === 'issue') issue();
else if (command === 'serve') serve();
else die('Usage: node scripts/dev-certs.mts [issue|serve] [--san <ip>]...');
