#!/usr/bin/env bash
# =============================================================================
#  DeltaForce MFA — repository scaffold
#  Creates the full empty file structure, laid out exactly as the shared
#  context block in prompt.md describes it. Run ONCE, from the repo root, by
#  UDK, and commit the result before anyone else starts work.
#
#    chmod +x scaffold.sh && ./scaffold.sh
#
#  Every file is created with a single header comment naming its owner
#  (UDK, RMR, DPC, WAI, JDH) and its purpose, so nobody has to guess where
#  their code goes — and so the first real commit from each member is an edit,
#  not a new file that collides with someone else's new file.
#
#  Safe to re-run: existing files are never overwritten.
# =============================================================================
set -euo pipefail

created=0
skipped=0

# new <path> <comment-line>
new() {
  local path="$1"; shift
  local body="${1:-}"
  if [ -e "$path" ]; then
    skipped=$((skipped + 1))
    return
  fi
  mkdir -p "$(dirname "$path")"
  if [ -n "$body" ]; then
    printf '%s\n' "$body" > "$path"
  else
    : > "$path"
  fi
  created=$((created + 1))
}

ts()   { new "$1" "// [$2] $3"; }          # .ts / .tsx
md()   { new "$1" "# $2"; }                # .md
hashc(){ new "$1" "# [$2] $3"; }           # .yml / .yaml / .sh / .env
sql()  { new "$1" "// [$2] $3"; }          # .prisma

# -----------------------------------------------------------------------------
# Root  (pnpm workspace)
# -----------------------------------------------------------------------------
new  package.json          '{ "name": "deltaforce-mfa", "private": true }'
new  pnpm-workspace.yaml   'packages:
  - "apps/*"
  - "packages/*"'
new  tsconfig.base.json    '{ "compilerOptions": { "strict": true, "target": "ES2022", "module": "ESNext", "moduleResolution": "bundler", "skipLibCheck": true } }'
hashc docker-compose.yml       UDK "PostgreSQL + Redis only, named volumes and health checks. Apps run with pnpm dev."
hashc .env.example             UDK "Every variable the config loader requires. Copy to .env. Never commit .env."
hashc traceability.yaml        JDH "R1-R10 and T1-T8 mapped to the task IDs and test names that discharge them"
md   README.md             "DeltaForce MFA"
md   CLAUDE.md             "DeltaForce MFA — project rules for AI-assisted development"

new .gitignore 'node_modules/
dist/
.env
keys/*.pem
*.log
test-results/
playwright-report/'

new  keys/.gitkeep ""

# -----------------------------------------------------------------------------
# Prisma + scripts + docs
# -----------------------------------------------------------------------------
sql  prisma/schema.prisma         UDK "users, password_credentials, authenticators, recovery_codes, auth_events (append-only, prev_hash), sessions"
ts   scripts/seed.ts              UDK "One account with a password and no second factor"
ts   scripts/make-keys.ts         UDK "Generate the server ECDSA P-256 signing key into keys/"

md   docs/decisions.md            "Implementation Decisions"
md   docs/wcag-mapping.md         "WCAG 2.2 Conformance Matrix"
md   docs/screen-reader-checklist.md "Screen Reader Test Checklist"
md   docs/tradeoffs.md            "Accessibility and Security Trade-off Register"

# -----------------------------------------------------------------------------
# packages/protocol  —  shared message schemas, canonical encoding, crypto
# -----------------------------------------------------------------------------
new  packages/protocol/package.json  '{ "name": "@deltaforce/protocol", "version": "0.0.0", "private": true, "type": "module", "main": "src/index.ts" }'
new  packages/protocol/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
ts   packages/protocol/src/index.ts           RMR "Barrel: re-exports types, encode, crypto, channel"
ts   packages/protocol/src/types.ts           RMR "Types + zod schemas for the six messages, notation constants, closed set of error codes"
ts   packages/protocol/src/encode.ts          RMR "Canonical length-prefixed encoder/decoder for the bytes sigma_s signs"
ts   packages/protocol/src/encode.test.ts     RMR "Round trip; unknown field rejected; no two field triples encode to the same bytes"
ts   packages/protocol/src/crypto.ts          RMR "32-byte CSPRNG nonces, X25519, HPKE seal/open, AES-256-GCM with a subkey per direction and message index as AAD"
ts   packages/protocol/src/crypto.test.ts     RMR "Known-answer tests; a message replayed in the other direction fails to decrypt"
ts   packages/protocol/src/channel.ts         DPC "SecondFactorChannel (enrol, challenge, verify, revoke) + the shared enrolment state machine"
ts   packages/protocol/src/mockChannel.ts     DPC "In-memory MockChannel so nobody needs Twilio or a phone to develop"
ts   packages/protocol/src/channel.conformance.test.ts DPC "Conformance suite every real channel must also pass"

# -----------------------------------------------------------------------------
# packages/policy  —  factor policy, rate limits, lockout rules
# -----------------------------------------------------------------------------
new  packages/policy/package.json  '{ "name": "@deltaforce/policy", "version": "0.0.0", "private": true, "type": "module", "main": "src/index.ts" }'
new  packages/policy/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
ts   packages/policy/src/index.ts             UDK "Barrel: re-exports factorPolicy, rateLimits, lockout"
ts   packages/policy/src/factorPolicy.ts      UDK "Factors the SERVER will accept for a user, FIDO2 first; a factor not offered is a downgrade attempt"
ts   packages/policy/src/factorPolicy.test.ts UDK "Voice requested when only a key is enrolled is rejected and audited"
ts   packages/policy/src/rateLimits.ts        JDH "Every rate limit in the system, declared in this one file"
ts   packages/policy/src/rateLimits.test.ts   JDH "Route handlers contain no limits of their own"
ts   packages/policy/src/lockout.ts           JDH "5 verify attempts SHARED across channel switches; lockout explains itself and gives a route out"
ts   packages/policy/src/lockout.test.ts      JDH "Switching channel does not reset the counter"

# -----------------------------------------------------------------------------
# packages/testkit  —  MITM proxy, attack suites, test helpers
# -----------------------------------------------------------------------------
new  packages/testkit/package.json  '{ "name": "@deltaforce/testkit", "version": "0.0.0", "private": true, "type": "module", "main": "src/index.ts" }'
new  packages/testkit/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
ts   packages/testkit/src/index.ts            JDH "Barrel: re-exports proxy, harness, helpers"
ts   packages/testkit/src/proxy.ts            JDH "Scriptable proxy between client and server: drop, reorder, replay, modify, impersonate either party"
ts   packages/testkit/src/harness.ts          JDH "Small API so one script can mount any of the four attack families"
ts   packages/testkit/src/helpers.ts          JDH "Shared test helpers: honest handshake, seeded users, transcript capture"
ts   packages/testkit/src/suites/replay.test.ts       JDH "Replay hello, old c2, old sigma_u; each rejection names its cause (T1, T2)"
ts   packages/testkit/src/suites/eavesdrop.test.ts    JDH "Full transcript of a successful login contains no secret in clear"
ts   packages/testkit/src/suites/mitm.test.ts         RMR "Lowe-style key substitution: SUCCEEDS against the weakened control, FAILS against ours"
ts   packages/testkit/src/suites/cutAndPaste.test.ts  RMR "Two servers with different S_id; spliced credential messages are refused"
ts   packages/testkit/src/suites/interleaving.test.ts RMR "Two concurrent sessions, reused nonce_u; swapped final replies are refused"

# -----------------------------------------------------------------------------
# apps/auth-server  —  Fastify + TS: protocol, policy and storage logic
# -----------------------------------------------------------------------------
new  apps/auth-server/package.json  '{ "name": "@deltaforce/auth-server", "version": "0.0.0", "private": true, "type": "module" }'
new  apps/auth-server/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
ts   apps/auth-server/src/index.ts  UDK "Entry point: builds the Fastify app and listens"
ts   apps/auth-server/src/app.ts    UDK "Fastify instance: HTTPS only, HSTS, strict CSP, CORS locked to the web origin, request id, redacting log serializer"
ts   apps/auth-server/src/config.ts UDK "zod-parsed config loader; the ONLY place that reads the environment; named error at boot"
ts   apps/auth-server/src/errors.ts UDK "Shared typed errors"

# db  —  UDK
ts   apps/auth-server/src/db/prisma.ts            UDK "PrismaClient singleton"
ts   apps/auth-server/src/db/kv.ts                UDK "Redis wrapper. Every key is written with a TTL."
ts   apps/auth-server/src/db/kv.test.ts           UDK "No write without a TTL; atomic get-and-delete"
ts   apps/auth-server/src/db/pendingAuth.ts       UDK "Pending-auth record: AWAITING_PASSWORD -> AWAITING_SECOND_FACTOR -> COMPLETE | FAILED; 10 min TTL; atomic transitions"
ts   apps/auth-server/src/db/pendingAuth.test.ts  UDK "Every legal transition; an illegal one is rejected; terminal records are unusable"
ts   apps/auth-server/src/db/replayCache.ts       UDK "Single-use consumption of nonce_s2 and the sigma_u digest; atomic"
ts   apps/auth-server/src/db/replayCache.test.ts  UDK "Fifty parallel submissions of one assertion, exactly one success"

# auth  —  passwords
ts   apps/auth-server/src/auth/password.ts            RMR "Argon2id m=19456 KiB t=2 p=1, 16-byte salt, rehash-on-login, constant-time compare"
ts   apps/auth-server/src/auth/password.test.ts       JDH "Unique salts; tamper fails; rehash only when parameters are stale; verify-time benchmark"
ts   apps/auth-server/src/auth/passwordPolicy.ts      RMR "NIST SP 800-63B: 8 to 64+ chars, any Unicode, no composition rules, local breached-password check"
ts   apps/auth-server/src/auth/passwordPolicy.test.ts RMR "Breached password rejected; 40-character passphrase with spaces accepted"
ts   apps/auth-server/src/auth/routes.ts              DPC "Registration and password-change endpoints; responses identical whether or not the account exists"
ts   apps/auth-server/src/auth/uniformResponse.ts     JDH "Dummy Argon2id verify for unknown users, fixed minimum duration, byte-identical errors"
ts   apps/auth-server/src/auth/uniformResponse.test.ts JDH "Two hundred requests cannot separate unknown user from wrong password"

# protocol  —  the six-message ceremony
ts   apps/auth-server/src/protocol/serverKey.ts      UDK "Key store interface + file-backed ECDSA P-256 key; exports the single S_id constant; rotation aborts in-flight handshakes cleanly"
ts   apps/auth-server/src/protocol/serverKey.test.ts UDK "Rotating the key mid-handshake produces a clean abort"
ts   apps/auth-server/src/protocol/tunnel.ts         RMR "Fastify plugin: steps 1 and 2 (sigma_s over nonce_u, PKEncKey_u, S_id), 4, 5b and 6"
ts   apps/auth-server/src/protocol/tunnel.test.ts    RMR "All three fields are inside the signature; a signature over the nonce alone fails"
ts   apps/auth-server/src/protocol/step3.ts          DPC "Decrypt c2, zod-validate, check nonce_s, then verify the password; grants nothing else"
ts   apps/auth-server/src/protocol/step3.test.ts     DPC "Correct password alone grants no access; stale nonce_s rejected before the hash is checked"
ts   apps/auth-server/src/protocol/traceLogger.ts    DPC "Development-only structured transcript of the six steps; never a secret; cannot be enabled in production"
ts   apps/auth-server/src/protocol/handshake.negative.test.ts JDH "Tampered sigma_s, substituted key, replayed c1, wrong S_id: each names the check that caught it (T3, T4)"
ts   apps/auth-server/src/protocol/handshakeAbuse.ts JDH "Per-IP hello rate limit, cap on pending records per identity, bounded memory"

# webauthn  —  RMR
ts   apps/auth-server/src/webauthn/registration.ts      RMR "Registration ceremony: RP ID from S_id, attestation none, user-assigned nickname"
ts   apps/auth-server/src/webauthn/registration.test.ts RMR "Re-registering the same credential is rejected"
ts   apps/auth-server/src/webauthn/assertion.ts         RMR "Step 5a: challenge IS nonce_s2 from the pending record, RP ID IS S_id; counter regression rejected"
ts   apps/auth-server/src/webauthn/assertion.test.ts    RMR "Wrong challenge refused; assertion minted for another origin refused"
ts   apps/auth-server/src/webauthn/virtualAuthenticator.test.ts JDH "Happy path, wrong RP ID, cloned key, replayed assertion — no hardware"

# otp + factors
ts   apps/auth-server/src/otp/otpService.ts       RMR "dec6(HMAC-SHA256(k_otp, nonce_s2 | U_id | channel)); stored only as a hash; 180 s; single use; bound to one pending record"
ts   apps/auth-server/src/otp/otpService.test.ts  RMR "One record never yields two codes; used code dies; code from another handshake refused"
ts   apps/auth-server/src/otp/otpAbuse.test.ts    JDH "Used, expired, cross-handshake, cross-user, brute force, log redaction (T2, T5)"
ts   apps/auth-server/src/factors/selection.ts      DPC "List offered factors (FIDO2 first) and record the choice; switching never resets the attempt counter"
ts   apps/auth-server/src/factors/selection.test.ts DPC "Three switches, counter keeps counting; unenrolled factor refused"
ts   apps/auth-server/src/factors/voice.ts          DPC "Twilio voice channel + mock driver: digits one at a time, spoken twice, DTMF to repeat"
ts   apps/auth-server/src/factors/voice.test.ts     DPC "Passes the channel conformance suite on the mock driver"
ts   apps/auth-server/src/factors/haptic.ts         UDK "Haptic channel: pairing by short code, device key, revocation"
ts   apps/auth-server/src/factors/haptic.test.ts    UDK "Refuses to pair with the browser session that is logging in"
ts   apps/auth-server/src/factors/hapticSocket.ts   UDK "Authenticated WebSocket registry keyed by device id; a revoked device is disconnected at once"
ts   apps/auth-server/src/factors/deliveryQueue.ts  UDK "Retry with backoff, user-safe errors, offer another channel on permanent failure; the OTP never enters logs"

# session
ts   apps/auth-server/src/session/sessionManager.ts      UDK "256-bit opaque id from a CSPRNG, state in Redis, NEW id minted when authentication completes"
ts   apps/auth-server/src/session/sessionManager.test.ts UDK "The pre-login identifier cannot be used after login"
ts   apps/auth-server/src/session/cookie.ts              UDK "__Host- cookie: Secure, HttpOnly, SameSite=Strict, Path=/; origin check on state-changing routes"
ts   apps/auth-server/src/session/lifetime.ts            RMR "Idle timeout, absolute lifetime, logout, bulk revocation on password change or authenticator removal"
ts   apps/auth-server/src/session/lifetime.test.ts       RMR "Removing an authenticator kills every live session for that user"
ts   apps/auth-server/src/session/session.attack.test.ts DPC "Fixation, stolen cookie after revocation, concurrent-session limit, timeout boundaries"

# lifecycle  —  authenticators, recovery, helpers
ts   apps/auth-server/src/lifecycle/authenticatorService.ts DPC "Create, list, rename, revoke; the raw phone number is never returned by a read"
ts   apps/auth-server/src/lifecycle/authenticatorRoutes.ts  UDK "Management API: list, rename, revoke behind step-up; revoking the last factor is refused"
ts   apps/auth-server/src/lifecycle/setupGuard.ts           UDK "R9: no leaving setup below two authenticators + acknowledged recovery codes; enforced server-side"
ts   apps/auth-server/src/lifecycle/recoveryCodes.ts        RMR "10 codes x 10 Crockford base32 characters; Argon2id-hashed; single use, atomic"
ts   apps/auth-server/src/lifecycle/recoveryCodes.test.ts   RMR "A code submitted twice concurrently succeeds only once"
ts   apps/auth-server/src/lifecycle/recovery.ts             RMR "Password + one recovery code; suspends the lost authenticator FIRST; replacement enrolled in the same session"
ts   apps/auth-server/src/lifecycle/recovery.test.ts        RMR "The suspended key cannot authenticate; abandoning leaves the account no weaker"
ts   apps/auth-server/src/lifecycle/recovery.abuse.test.ts  JDH "Rate limited, no code reuse, no unauthenticated recovery (T7, R4)"
ts   apps/auth-server/src/lifecycle/notifications.ts        DPC "One plain-text notice per enrolment, revocation, recovery and password change"
ts   apps/auth-server/src/lifecycle/helperGrant.ts          JDH "R7: scoped, time-boxed, revocable helper grant; never a password, OTP or recovery code"
ts   apps/auth-server/src/lifecycle/helperGrant.test.ts     JDH "Permitted steps only; expires by itself; every action attributable"

# audit  —  JDH
ts   apps/auth-server/src/audit/auditLog.ts       JDH "Nine event types, each row hash-chained to the previous; never a password, code, token or key"
ts   apps/auth-server/src/audit/auditLog.test.ts  JDH "Altering one row breaks the chain and the verifier names the row"
ts   apps/auth-server/src/audit/routes.ts         JDH "GET /api/audit"

# -----------------------------------------------------------------------------
# apps/web  —  React + Vite: the accessible client  (WAI)
# -----------------------------------------------------------------------------
new  apps/web/package.json  '{ "name": "@deltaforce/web", "version": "0.0.0", "private": true, "type": "module" }'
new  apps/web/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
new  apps/web/index.html '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DeltaForce</title></head><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>'
ts   apps/web/vite.config.ts   WAI "Dev server; proxies API and protocol routes to the auth server"
ts   apps/web/src/main.tsx     WAI "React root"
ts   apps/web/src/App.tsx      WAI "App shell: routing, skip link, landmarks, page title on every route change"
new  apps/web/src/styles.css   "/* [WAI] Tokens, .visually-hidden, focus-visible, prefers-reduced-motion */"

ts   apps/web/src/lib/protocol-client.ts       WAI "Ephemeral X25519 key, hello, and the THREE step-2 checks; any failure aborts before a password field renders"
ts   apps/web/src/lib/protocol-client.test.ts  WAI "Each of the three checks failing leaves no password field at all"
ts   apps/web/src/lib/announcer.ts             WAI "The single announcer service: one polite and one assertive live region"
ts   apps/web/src/lib/api.ts                   WAI "Plain fetch helpers for the non-protocol REST routes"

ts   apps/web/src/components/index.ts              WAI "Barrel — this is what the other members import"
ts   apps/web/src/components/StepHeading.tsx       WAI "h1 tabIndex=-1, takes focus on mount (WCAG 2.4.3)"
ts   apps/web/src/components/LiveRegion.tsx        WAI "Visually hidden aria-live region (WCAG 4.1.3)"
ts   apps/web/src/components/ErrorSummary.tsx      WAI "Errors in a live region, focus to the summary, each entry linked to its field (WCAG 3.3.1, 3.3.3)"
ts   apps/web/src/components/Alert.tsx             WAI "role=alert; icon AND text, never colour alone"
ts   apps/web/src/components/FormField.tsx         WAI "Real label, aria-describedby hint, never a placeholder as a label"
ts   apps/web/src/components/RecoveryCodes.tsx     WAI "NEVER read aloud automatically; explicit read / download / copy, each confirming audibly"
ts   apps/web/src/components/SessionExpiry.tsx     WAI "Warning before the idle timeout with a control to extend; nobody is silently logged out"
ts   apps/web/src/components/components.a11y.test.ts WAI "axe: zero violations; StepHeading takes focus"
ts   apps/web/src/components/otp/OtpTimer.tsx      WAI "Announces remaining time at 120 / 60 / 30 s ONLY, never a continuous countdown"
ts   apps/web/src/components/otp/OtpEntry.tsx      WAI "ONE input, inputmode numeric, one-time-code autocomplete, paste allowed"
ts   apps/web/src/components/otp/AudioOptIn.tsx    WAI "R5: explicit per-use confirmation with a shared-space warning before ANY code is spoken"
ts   apps/web/src/components/otp/otp.a11y.test.ts  WAI "axe + the three announcement thresholds"

ts   apps/web/src/flows/LoginFlow.tsx                 WAI "Orchestrates the steps; state lives in loginReducer"
ts   apps/web/src/flows/loginReducer.ts               WAI "No step is reachable by URL alone"
ts   apps/web/src/flows/EnrolmentWizard.tsx           WAI "Cannot finish below 2 authenticators + recovery codes (R9)"
ts   apps/web/src/flows/RecoveryFlow.tsx              WAI "Reachable without the lost factor; replacement enrolled inside the same flow"
ts   apps/web/src/flows/steps/UsernameStep.tsx        WAI ""
ts   apps/web/src/flows/steps/HandshakeStep.tsx       WAI "Polite 'securing connection'; on a binding failure, assertive and no way back to a login form"
ts   apps/web/src/flows/steps/PasswordStep.tsx        WAI "Paste MUST stay enabled — password managers"
ts   apps/web/src/flows/steps/FactorChooserStep.tsx   WAI "Radiogroup; only server-offered factors, FIDO2 announced as recommended"
ts   apps/web/src/flows/steps/SecurityKeyStep.tsx     WAI "navigator.credentials.get; explains the browser prompt BEFORE it appears; timeout announced"
ts   apps/web/src/flows/steps/OtpStep.tsx             WAI "Hosts the OTP components from components/otp; call-me-again and replay controls"
ts   apps/web/src/flows/steps/SuccessStep.tsx         WAI "Announces 'Signed in'"
ts   apps/web/src/flows/__stubs__/protocol.ts         WAI "TEMPORARY — fixture messages until the real handshake lands"

ts   apps/web/src/pages/Home.tsx                 WAI ""
ts   apps/web/src/pages/Authenticators.tsx       WAI "Accessible names include the authenticator nickname"
ts   apps/web/src/pages/AuditLog.tsx             WAI "Recent activity: real table, plain-language rows, filterable by date"
ts   apps/web/src/pages/AuditLog.a11y.test.ts    WAI "axe + keyboard reach + filter announcement"

# -----------------------------------------------------------------------------
# apps/haptic-sim  —  PWA: the paired vibration device  (UDK; encoding is DPC)
# -----------------------------------------------------------------------------
new  apps/haptic-sim/package.json  '{ "name": "@deltaforce/haptic-sim", "version": "0.0.0", "private": true, "type": "module" }'
new  apps/haptic-sim/tsconfig.json '{ "extends": "../../tsconfig.base.json" }'
new  apps/haptic-sim/index.html '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="manifest" href="/manifest.webmanifest"><title>DeltaForce Haptic</title></head><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>'
new  apps/haptic-sim/public/manifest.webmanifest '{ "name": "DeltaForce Haptic", "short_name": "Haptic", "start_url": "/", "display": "standalone" }'
new  apps/haptic-sim/public/sw.js "// [UDK] Minimal service worker — required for PWA install"
ts   apps/haptic-sim/vite.config.ts        UDK "Dev server over HTTPS (the Vibration API needs a secure context on a real handset)"
ts   apps/haptic-sim/src/main.tsx          UDK ""
ts   apps/haptic-sim/src/App.tsx           UDK "Pairing screen + idle screen + Replay. CODE IS NEVER RENDERED."
ts   apps/haptic-sim/src/vibration.ts      DPC "Vibration encoding: preamble, N short pulses per digit, inter-digit gap, own form for zero, long end marker"
ts   apps/haptic-sim/src/vibration.test.ts DPC "Round-trip decode every digit 0-9, repeated digits included"
ts   apps/haptic-sim/src/keystore.ts       UDK "The device's own key, non-extractable, in IndexedDB"
ts   apps/haptic-sim/src/socket.ts         UDK "Authenticated WebSocket: prove the device key, then receive the pattern"
ts   apps/haptic-sim/src/pairing.ts        UDK "Pair with the short code shown in the web app; refuse if this is the session logging in"

# -----------------------------------------------------------------------------
# tests  —  end-to-end, across apps
# -----------------------------------------------------------------------------
ts   tests/e2e/a11y.spec.ts          UDK "Accessibility gate: axe on every route in every authentication state"
ts   tests/e2e/login.spec.ts         DPC "Complete login through the real HTTP stack for each of the three second factors"
ts   vitest.config.ts                UDK "Workspace-wide unit test config"
ts   playwright.config.ts            UDK "Chromium; virtual authenticator enabled"

# -----------------------------------------------------------------------------
# CI
# -----------------------------------------------------------------------------
hashc .github/workflows/ci.yml JDH "typecheck, lint, unit tests, osv-scanner, gitleaks, traceability check — all blocking"

echo
echo "DeltaForce scaffold complete."
echo "  created: $created"
echo "  skipped (already existed): $skipped"
echo
echo "Next:"
echo "  1. git add -A && git commit -m 'chore: scaffold repository structure'"
echo "  2. Push before anyone starts — these files existing is what prevents"
echo "     five members creating the same folders in five conflicting commits."
echo "  3. Each member edits only the files marked with their own tag."
