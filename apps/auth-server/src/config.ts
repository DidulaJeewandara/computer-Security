import { z } from 'zod';
const urlWithProtocols = (protocols: string[]) => z.string().url().refine(value => {
  try { return protocols.includes(new URL(value).protocol); } catch { return false; }
});
const schema = z.object({
  DATABASE_URL: urlWithProtocols(['postgresql:', 'postgres:']),
  REDIS_URL: urlWithProtocols(['redis:', 'rediss:']),
  WEB_ORIGIN: z.string().url().refine(value => {
    const url = new URL(value);
    return url.protocol === 'https:' && value === url.origin;
  }),
  TLS_CERT_FILE: z.string().min(1),
  TLS_KEY_FILE: z.string().min(1),
  DATA_ENCRYPTION_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/),
  HOST: z.string().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
});
export class ConfigError extends Error {
  constructor(fields: string[]) {
    super(`CONFIG_INVALID: missing or malformed ${[...new Set(fields)].join(', ')}`);
    this.name = 'ConfigError';
  }
}
export function loadConfig(env: Record<string, string | undefined> = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) throw new ConfigError(parsed.error.issues.map(issue => String(issue.path[0])));
  const c = parsed.data;
  return Object.freeze({ databaseUrl: c.DATABASE_URL, redisUrl: c.REDIS_URL, webOrigin: c.WEB_ORIGIN,
    tlsCertFile: c.TLS_CERT_FILE, tlsKeyFile: c.TLS_KEY_FILE, dataEncryptionKey: c.DATA_ENCRYPTION_KEY,
    host: c.HOST, port: c.PORT, nodeEnv: c.NODE_ENV });
}
export type Config = ReturnType<typeof loadConfig>;
export function loadSeedConfig(env: Record<string, string | undefined> = process.env) {
  const parsed = z.object({ SEED_USERNAME: z.string().min(1).max(128), SEED_PASSWORD: z.string().min(8).max(1024) }).safeParse(env);
  if (!parsed.success) throw new ConfigError(parsed.error.issues.map(issue => String(issue.path[0])));
  return { username: parsed.data.SEED_USERNAME, password: parsed.data.SEED_PASSWORD };
}
