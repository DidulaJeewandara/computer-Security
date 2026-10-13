# UDK P0/P1 requirements and TDD plan

Source: prompt.md, shared context and the four UDK tasks below.

| Task | Required behavior | Acceptance evidence |
| --- | --- | --- |
| P0-UDK-1 | Exactly three apps and three packages; pnpm; strict TypeScript; root build/lint/test/dev; ESLint/Prettier; documented commands | scaffold.test.mjs plus install/build/lint |
| P0-UDK-2 | PostgreSQL/Redis with named volumes and health checks; documented environment; Zod boundary; only loader reads environment; safe named boot errors | config.test.ts, services.integration.test.ts |
| P1-UDK-1 | Users, password hash and Argon2 parameters, three authenticator types, nickname, public key/channel address, lifecycle timestamps; recovery hash/used timestamp; append-only chained-ready events; sessions | database.integration.test.ts |
| P1-UDK-1 | Encrypt sensitive phone addresses and credential IDs at rest; expose masked hints only; seed one password account with zero factors; verify via service | userService.test.ts, database.integration.test.ts |
| P1-UDK-2 | HTTPS-only listener; HSTS; strict CSP without inline script; exact web-origin CORS; server-generated request IDs; recursive case-insensitive field redaction | app.test.ts |
| Shared | Password Argon2id m=19456 KiB,t=2,p=1,random 16-byte salt; no secrets in logs/URLs/errors; validate boundaries; tests accompany code | seed verification and log capture |

Sequence: write tests → observe expected failures → implement minimal behavior →
run acceptance checks → refactor and rerun. Keep one local commit/branch per task.
Branches depend on preceding UDK tasks; PRs need teammate review before merging.

Password hashing is RMR's responsibility. UDK's user service accepts a verifier;
the seed uses the specified Argon2id parameters without implementing RMR's
rehash or password-policy work. Requirement numbers beyond explicit R9 must be
confirmed against the design document; supporting infrastructure links are not
claims that a whole requirement is completed.

Database and Redis integration checks require running local services. Never
substitute mocks for evidence that a migration works from empty.
