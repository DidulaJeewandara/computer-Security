// [RMR] Turn a plaintext password list into the SHA-1 file the policy loads. Usage: node scripts/build-breach-list.ts <in.txt> <out.txt>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const MIN_CHARS = 8; // shorter ones are already rejected by length

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error('usage: node scripts/build-breach-list.ts <in.txt> <out.txt>');
  process.exit(1);
}

const sha1 = (s: string) => createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();
const hashes = new Set<string>();

for (const line of readFileSync(input, 'utf8').split('\n')) {
  const raw = line.replace(/\r$/, '');
  const normalized = raw.normalize('NFKC');
  if (!raw || [...normalized].length < MIN_CHARS) continue;
  hashes.add(sha1(raw));
  hashes.add(sha1(normalized));
}

writeFileSync(output, [...hashes].sort().join('\n') + '\n');
console.log(`${hashes.size} hashes written`);
