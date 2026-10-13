import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
describe('P0-UDK-2 local services contract', () => {
  it('defines isolated PostgreSQL and Redis with persistence and readiness checks', () => {
    const compose = parse(readFileSync('docker-compose.yml', 'utf8'));
    for (const name of ['postgres', 'redis']) {
      const service = compose.services[name];
      expect(service.image).toMatch(new RegExp(`^${name}:`));
      expect(service.healthcheck.test.length).toBeGreaterThan(1);
      expect(service.volumes[0]).toMatch(new RegExp(`^${name}_data:`));
      expect(compose.volumes).toHaveProperty(`${name}_data`);
      expect(service.ports[0]).toMatch(/^127\.0\.0\.1:/);
    }
  });
});
