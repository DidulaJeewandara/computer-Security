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

Database setup (from the repository root):

1. `pnpm db:generate` generates the Prisma client (also runs on install).
2. `pnpm db:migrate` applies committed migrations to the configured database.
3. Set `SEED_USERNAME` and `SEED_PASSWORD` in `.env`, then `pnpm db:seed`.
   Existing seed accounts are preserved; seeding never resets a password.
4. Run `node --env-file=.env node_modules/vitest/vitest.mjs run
apps/auth-server/src/db/database.integration.test.ts` with `UDK_INTEGRATION=1`
   to exercise real PostgreSQL. The suite creates and drops only a randomly named
   test schema. Use a dedicated local test database, with schema-creation rights.

Sensitive authenticator identifiers use AES-256-GCM ciphertext and masked hints.
Use `prepareAuthenticatorData` for persistence and `publicAuthenticator` for
presentation. Keep `DATA_ENCRYPTION_KEY` stable and outside source control;
back it up separately from the database. Sessions store a digest, never a raw
session token. The later Redis session manager remains a separate UDK task.
Audit-event triggers reject updates, deletes and truncation. Production database
roles must not own tables or have permission to disable triggers.
