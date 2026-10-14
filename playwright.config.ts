// [UDK] Chromium; virtual authenticator enabled
// Minimal config added by P3-JDH-1 so the WebAuthn suite can run; UDK's accessibility gate
// (P7-UDK-1) extends it.
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/e2e',
  testMatch: '**/*.spec.ts',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  // Chromium only: the virtual authenticator is driven over the Chrome DevTools Protocol.
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
