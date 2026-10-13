import { buildApp } from './app.js';
import { ConfigError, loadConfig } from './config.js';
import { TlsConfigError } from './tls.js';
async function start() {
  const config = loadConfig();
  const app = await buildApp(config);
  const close = async () => {
    await app.close();
  };
  process.once('SIGINT', close);
  process.once('SIGTERM', close);
  await app.listen({ host: config.host, port: config.port });
}
start().catch((error) => {
  console.error(
    error instanceof ConfigError || error instanceof TlsConfigError
      ? `${error.name}: ${error.message}`
      : 'BOOT_FAILED: server could not start',
  );
  process.exitCode = 1;
});
