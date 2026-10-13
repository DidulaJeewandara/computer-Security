import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
const json = (path) => JSON.parse(readFileSync(path, 'utf8'));
test('P0-UDK-1: six workspaces have executable build and development commands', () => {
  for (const dir of [
    'apps/auth-server',
    'apps/web',
    'apps/haptic-sim',
    'packages/protocol',
    'packages/policy',
    'packages/testkit',
  ]) {
    const manifest = json(`${dir}/package.json`);
    assert.ok(manifest.scripts?.build, `${dir}: build missing`);
    assert.ok(manifest.scripts?.dev, `${dir}: dev missing`);
  }
});
test('P0-UDK-1: root exposes required commands and lint/format configuration', () => {
  const root = json('package.json');
  for (const command of ['build', 'lint', 'test', 'dev'])
    assert.ok(root.scripts?.[command], command);
  assert.equal(json('tsconfig.base.json').compilerOptions.strict, true);
  assert.ok(existsSync('eslint.config.js'));
  assert.ok(existsSync('.prettierrc.json'));
  const readme = readFileSync('README.md', 'utf8');
  for (const command of ['install', 'build', 'lint', 'test', 'dev'])
    assert.ok(readme.includes(`pnpm ${command}`));
});
