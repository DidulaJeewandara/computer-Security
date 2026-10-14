# Argon2id verify-time benchmark (P1-JDH-2)

Measured with `pnpm bench:argon2` (`apps/auth-server/src/auth/password.bench.ts`), 50 samples after 5 warm-up runs, calling the real `verifyPassword` at the shared-context parameters.

| Parameters                                       | Machine                                                                      | Node    | Mean                                                 | p75               | p99               |
| ------------------------------------------------ | ---------------------------------------------------------------------------- | ------- | ---------------------------------------------------- | ----------------- | ----------------- |
| m=19456 KiB, t=2, p=1, 16-byte salt, 32-byte tag | Intel Core i7-1165G7 (4 cores / 8 threads, 2.80 GHz), 7.5 GiB RAM, Linux 6.8 | 24.21.0 | 23.7 ms (correct password), 24.5 ms (wrong password) | 24.6 ms / 25.7 ms | 29.4 ms / 28.7 ms |

Measured on 2026-10-14 on JDH's laptop. If the demo runs on a different machine, rerun `pnpm bench:argon2` there and add a row.

## Against the 500 ms target in P1-JDH-2

P1-JDH-2 says to raise the memory cost if verify time is far below 500 milliseconds. At about 24 ms it is roughly twenty times below that.

The parameters have **not** been changed. The shared context in `prompt.md` fixes Argon2id at m=19456 KiB, t=2, p=1 and says not to invent alternatives, so raising the cost is a team decision, not something this task can do on its own. Things to weigh if the team does raise it:

- Each password attempt already costs 19 MiB of server memory (P2-JDH-2 relies on this figure for its flood limits); a higher m raises the cost of an unauthenticated flood too.
- `NOTATION.ARGON2ID` in `packages/protocol/src/constants.ts` is the single place to change it, and the rehash-on-login path (`verifyAndUpgrade`) upgrades existing hashes automatically at the next successful login.

Quote this measured figure in the report rather than the design document's theoretical one.
