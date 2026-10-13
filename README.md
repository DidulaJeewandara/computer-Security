# DeltaForce MFA

Requires Node.js 20.19+ and pnpm 10.15.1.

- `pnpm install --frozen-lockfile`: install all workspace dependencies.
- `pnpm build`: compile all six TypeScript workspaces.
- `pnpm typecheck`: check workspace types.
- `pnpm lint`: run ESLint.
- `pnpm test`: run platform acceptance and unit tests.
- `pnpm dev`: watch all workspaces during development.
- `pnpm format` / `pnpm format:check`: format / check formatting.

Apps: `auth-server` (Fastify), `web` (React/Vite), `haptic-sim` (companion PWA).
Packages: `protocol`, `policy`, `testkit`. Files marked with a member's code are
interfaces/placeholders until that member implements them.

Local services: copy `.env.example` to `.env`, replace the password and encryption
key, then run `docker compose up -d --wait`. Use mkcert as documented in
[development certificates](docs/dev-certificates.md). All server variables are
parsed by `apps/auth-server/src/config.ts`; other code receives configuration.
Run the server with `pnpm --filter @deltaforce/auth-server dev`.
