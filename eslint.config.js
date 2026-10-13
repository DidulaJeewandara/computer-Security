import js from '@eslint/js';
import tseslint from 'typescript-eslint';
export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'playwright-report/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ['**/*.{js,mjs,ts,tsx,mts}'], languageOptions: { globals: { console: 'readonly', process: 'readonly', Buffer: 'readonly', crypto: 'readonly', URL: 'readonly', TextEncoder: 'readonly', TextDecoder: 'readonly', CryptoKey: 'readonly', fetch: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly' } } },
);
