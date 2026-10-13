import { ConfigError, loadConfig } from './config.js';
try {
  loadConfig();
  // P1-UDK-2 wires the HTTPS listener after server-hardening tests are written.
} catch (error) {
  console.error(error instanceof ConfigError ? `${error.name}: ${error.message}` : 'BOOT_FAILED');
  process.exitCode = 1;
}
