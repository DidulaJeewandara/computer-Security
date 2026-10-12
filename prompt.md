# DeltaForce MFA — Build Prompts by Member

Oct 12, 2026 · @didula

Each person pastes the shared context block once at the start of their session, then runs their own eighteen prompts in order: ten on day one, eight on day two, one prompt per task, one branch and one pull request per prompt.

## How to use these prompts

- Open a session in the repository and paste the shared context block below. Do it once per session; if you start a fresh session on day two, paste it again.
- Run your own prompts in order. They are numbered, and a later prompt assumes the earlier ones landed.
- One prompt is one task: branch, do the work, open a pull request titled with the task ID, get one teammate to review.
- Read what comes back before you accept it. The prompt states the acceptance criteria; if the result does not meet them, say which one failed rather than starting again.
- If a prompt depends on someone else's work that is not merged yet, build against the interface and a stub, and say so in the pull request. The merge order section at the end says which ones those are.
- Do not let a session invent values. Every number this project needs is already fixed in the shared context block.

## Shared context — paste this first

```text
We are building an accessible multi-factor authentication system for blind and
partially sighted users, from team DeltaForce's architecture and design document.

MONOREPO (pnpm, TypeScript everywhere)
  apps/auth-server    Fastify + TS   protocol, policy and storage logic
  apps/web            React + Vite   the accessible client
  apps/haptic-sim     PWA            the paired vibration device
  packages/protocol   shared message schemas, canonical encoding, crypto
  packages/policy     factor policy, rate limits, lockout rules
  packages/testkit    MITM proxy, attack suites, test helpers
  PostgreSQL via Prisma for durable data. Redis for ephemeral state, always
  with a TTL.

WHAT IT DOES
  Password or passphrase (knowledge factor), then ONE second factor the user
  already enrolled: a FIDO2/WebAuthn security key, a voice-call OTP, or a
  haptic vibration OTP on a paired companion device.

THE PROTOCOL is a six-message ceremony running INSIDE TLS, not instead of it:
  1. u to s   U_id, S_id, nonce_u, PKEncKey_u
  2. s to u   sigma_s = Sign_s(nonce_u | PKEncKey_u | S_id),
              c1 = Enc(PKEncKey_u, key), nonce_s
  3. u to s   c2 = Enc_key(password | nonce_s)
  4. s to u   c3 = Enc_key(nonce_s2)
  5. u to s   c4 = Enc_key(sigma_u), sigma_u = Sign_u(nonce_s2 | S_id)
  6. s to u   Enc_key(OK)
  Step 5 has two forms. 5a is a WebAuthn assertion whose challenge IS nonce_s2
  and whose RP ID IS S_id. 5b is a six-digit OTP derived from nonce_s2.
  Signing nonce_u together with PKEncKey_u and S_id is the channel binding; it
  is what defeats the Lowe-style man-in-the-middle attack. Never weaken it.

FIXED VALUES - do not invent alternatives
  PKEnc        HPKE (RFC 9180), X25519-HKDF-SHA256 with AES-256-GCM
  sigma_s      ECDSA P-256 over a LENGTH-PREFIXED encoding of the three fields
  Enc_key      AES-256-GCM, separate subkey per direction, message index as AAD
  Passwords    Argon2id, m=19456 KiB, t=2, p=1, 16-byte random salt
  OTP          6 decimal digits, dec6(HMAC-SHA256(k_otp, nonce_s2 | U_id |
               channel)), valid 180 s, stored only as a hash, single use
  Pending auth 10 minute TTL, single use, 5 verify attempts SHARED across any
               switch between second-factor channels
  Nonces       32 bytes from a CSPRNG. Never timestamps.
  Session id   256 bits from a CSPRNG, opaque, regenerated at login
  S_id         the WebAuthn RP ID, auth.deltaforce.lk
  Recovery     10 codes, 10 Crockford base32 characters, Argon2id-hashed

NON-NEGOTIABLE CONSTRAINTS
  - No code is ever spoken aloud by default. Audio output of an OTP or a
    recovery code needs an explicit per-use opt-in with a shared-space warning.
  - Everything is keyboard operable and meets WCAG 2.2 AA. No path may require
    a cognitive function test: password managers and paste always work.
  - No password, OTP, recovery code, session token or key may appear in any
    log, URL or error message.
  - The SERVER decides which factors are allowed. A client request can never
    select a factor the server did not offer, and never downgrade.
  - The haptic device is a separate registered companion, never the machine
    being logged in from.

HOUSE RULES
  zod-validate every boundary, including the decrypted contents of c2 and c4.
  One task = one branch = one pull request, titled with its task ID.
  Write the test in the same pull request as the code.
  Add the task ID to traceability.yaml against the requirement it discharges.
  Prefer Node's own crypto over a third-party primitive wherever it exists.
```

## Nethsara U.D.K.C. (UDK) — Platform and data

You build what the other four stand on: repository, database, Redis state, sessions, deployment. Prompts 1 and 2 unblock everybody, so run them first and merge them before anyone else starts.

### Day 1

#### 1 · P0-UDK-1 — Monorepo scaffold

```text
Scaffold the pnpm monorepo exactly as the shared context describes: the three
apps and three packages, a shared base tsconfig with strict mode on, ESLint and
Prettier wired at the root, and root scripts for build, lint, test and dev. Add
a README listing the commands.
Acceptance: a clean clone runs install and build with no errors, and lint passes
on the empty packages.
```

#### 2 · P0-UDK-2 — Local services and config loader

```text
Add docker-compose with PostgreSQL and Redis, both with named volumes and health
checks, plus a .env.example listing every variable. Write a config loader in
apps/auth-server that parses the environment with a zod schema and throws a
named error at boot when something required is missing or malformed. Nothing
outside that loader may read the environment directly.
Acceptance: deleting one required variable produces a message naming it, not a
stack trace.
```

#### 3 · P1-UDK-1 — Database schema v1

```text
Design the Prisma schema and first migration: users; password_credentials with
hash and parameters; authenticators with type fido2 or voice or haptic, a
user-assigned nickname, the public key or channel address, created_at,
last_used_at and revoked_at; recovery_codes with hash and used_at; auth_events
as append-only with a prev_hash column ready for chaining; sessions. Phone
numbers and credential identifiers must be stored so they are never rendered in
full. Add a seed creating one account with a password and no second factor.
Acceptance: migrating from empty succeeds and the seeded account authenticates
through the service layer.
```

#### 4 · P1-UDK-2 — Server hardening

```text
Harden the Fastify server: HTTPS only, HSTS, a strict Content-Security-Policy
with no inline script, CORS locked to the web app origin, a request id on every
request, and a log serializer that redacts any field named password, otp, code,
token, cookie, authorization or secret.
Acceptance: a test posts a password and asserts it appears nowhere in captured
log output.
```

#### 5 · P2-UDK-1 — Pending-authentication store

```text
Implement the pending-authentication store in Redis: a record created at
protocol step 1 with states AWAITING_PASSWORD, AWAITING_SECOND_FACTOR, COMPLETE
and FAILED, a 10 minute TTL, an attempt counter, the issued nonce_s and
nonce_s2, and the selected factor. Transitions must be atomic, and a record in a
terminal state must be unusable. No password, session key or OTP may be stored
in it.
Acceptance: tests cover every legal transition and prove an illegal one is
rejected.
```

#### 6 · P2-UDK-2 — Server key store and S_id

```text
Add a key store behind an interface with one file-backed implementation holding
the server's ECDSA P-256 signing key, and a single exported S_id constant used
by BOTH the protocol signer and the WebAuthn relying-party config, so the two
can never disagree. Document the rotation procedure, and make rotation abort
in-flight handshakes cleanly rather than crashing them.
Acceptance: a test rotates the key mid-handshake and observes a clean abort.
```

#### 7 · P3-UDK-1 — Replay cache

```text
Implement the replay cache in Redis: single-use consumption of nonce_s2 and of
the sigma_u digest, with a TTL at least as long as the pending-auth lifetime.
Consumption must be atomic so that concurrent submissions of the same assertion
cannot both succeed.
Acceptance: a concurrency test fires fifty parallel submissions of one valid
assertion and counts exactly one success.
```

#### 8 · P3-UDK-2 — Factor policy engine

```text
Build the factor policy engine in packages/policy: given a user it returns the
second factors the server will accept, ordered with FIDO2 first. The
verification path must read the allowed factor from the server-side pending
record, never from the request body. A request naming a factor that was not
offered is rejected and recorded as a downgrade attempt.
Acceptance: a crafted request asking for voice when only a key is enrolled is
rejected and appears in the audit trail as a downgrade attempt.
```

#### 9 · P4-UDK-1 — Haptic companion PWA

```text
Build apps/haptic-sim: a PWA that pairs to an account using a short code shown
in the web app, holds its own device key, connects over an authenticated
WebSocket, plays a vibration pattern with the Vibration API, offers a replay
control, and can be revoked from the server. It must refuse to pair when it is
the same browser session that is logging in.
Acceptance: pairing, delivery, replay and revocation all work on a real Android
handset over HTTPS.
```

#### 10 · P4-UDK-2 — Delivery queue and failure handling

```text
Add a delivery queue in front of the channel gateway: retry with exponential
backoff, provider errors mapped to user-safe accessible messages, automatic
offer of another enrolled channel when one fails permanently, and an audit event
for every delivery attempt. The OTP must never enter the queue's logs or its
error objects.
Acceptance: with an invalid provider credential the user gets a clear error and
is offered their other channel.
```

### Day 2

#### 11 · P5-UDK-1 — Session manager

```text
Implement the session manager: a 256-bit opaque identifier from a CSPRNG, state
held server-side in Redis, and a NEW identifier minted at the moment
authentication completes so the pre-login identifier becomes worthless. The
record holds the user id, which factor was used, issued-at and last-seen, and no
secret of any kind.
Acceptance: a test captures the pre-login identifier and proves it cannot be
used after login.
```

#### 12 · P5-UDK-2 — Cookie and request hardening

```text
Set the session cookie Secure, HttpOnly, SameSite=Strict, Path=/ and with the
__Host- prefix, and make certain the identifier never appears in a URL, a log
line or an error. Add an origin check on every state-changing route.
Acceptance: a cross-site form post against a logged-in session is rejected.
```

#### 13 · P6-UDK-1 — Two-authenticator rule

```text
Enforce requirement R9 server-side: an account cannot leave setup state until it
has at least two registered authenticators and has acknowledged its recovery
codes. Until then only the setup routes are reachable. The check must run on the
server and be impossible to skip by calling the API directly.
Acceptance: a direct API call to a protected route from a half-set-up account is
refused with an accessible explanation of what is missing.
```

#### 14 · P6-UDK-2 — Authenticator management

```text
Build the authenticator management API: list with nickname, type and last-used;
rename; and revoke behind step-up authentication. Revoking the last remaining
factor is refused. Revocation propagates at once, so a revoked haptic device
disconnects and a revoked key stops verifying.
Acceptance: tests cover rename, revoke, the last-factor guard and propagation.
```

#### 15 · P7-UDK-1 — Automated accessibility gate

```text
Add an accessibility gate to CI: Playwright visits every route in every
authentication state, including authenticated ones via a seeded session, runs
axe-core, and fails the build on any serious or critical violation.
Acceptance: deliberately removing a form label fails the build, and the output
names the offending element.
```

#### 16 · P7-UDK-2 — Screen-reader walkthrough runs

```text
Run and record the manual screen-reader walkthroughs: NVDA with Firefox,
VoiceOver with Safari, TalkBack with Chrome, across login with each of the three
factors, key enrolment, and account recovery. For each run record what was
announced, where focus went, and anything unclear, and file every defect with a
severity.
Acceptance: the completed walkthrough records are committed under docs/.
```

#### 17 · P8-UDK-1 — Deployment

```text
Produce the deployment: container images for server and web app, a reverse proxy
with TLS 1.3 and HSTS, migrations run on deploy, health checks, and every secret
injected from the environment rather than baked into an image.
Acceptance: the demo runs against a deployed instance over real TLS, not a
development server.
```

#### 18 · P8-UDK-2 — Operational hardening

```text
Finish operational hardening: verify log redaction across the whole test suite,
pin every dependency and generate an SBOM, and carry out a backup and restore
drill of the user database, documenting the steps.
Acceptance: a restore from backup produces a system that still logs the seeded
user in.
```

## Chathuranga R.M.R (RMR) — Protocol and cryptography

Yours is the hardest share: the six-message ceremony and both forms of the possession factor. Prompt 6 is the one the whole security analysis rests on — do not let anything simplify the signature.

### Day 1

#### 1 · P0-RMR-1 — Protocol types and schemas

```text
In packages/protocol, define TypeScript types and zod schemas for all six
protocol messages, the notation constants from the shared context, and a closed
set of error codes. Add a canonical, length-prefixed encoder and decoder for the
byte string that sigma_s signs, so the signer and the verifier can never
disagree about where one field ends and the next begins.
Acceptance: a round-trip test encodes and decodes every message; an unknown
field is rejected; two different field triples can never produce the same
encoded bytes.
```

#### 2 · P0-RMR-2 — Development certificate authority

```text
Set up a local development certificate authority with mkcert and issue a server
certificate for auth.deltaforce.lk. Write the trust-store installation steps for
macOS, Windows and Linux in docs, because every member needs them. The client
must validate the chain properly; do not disable verification anywhere, not even
in tests.
Acceptance: all five machines reach the server over HTTPS with no browser
warning, and a test proves an untrusted certificate is rejected.
```

#### 3 · P1-RMR-1 — Argon2id service

```text
Implement the password hashing service using Argon2id with the parameters in the
shared context and a 16-byte random salt. Store the encoded hash including its
own parameters, and add a rehash-on-login path that silently upgrades a hash
made with older parameters after a successful verify. Comparison must be
constant time.
Acceptance: a hash created with weaker parameters is upgraded at the next
successful login, and the test asserts the stored parameters changed.
```

#### 4 · P1-RMR-2 — Password and passphrase policy

```text
Implement the credential policy to NIST SP 800-63B: accept 8 to at least 64
characters, allow spaces and any Unicode, impose no composition rules, never
force rotation, and check the candidate against a locally held breached-password
list using k-anonymity so the password never leaves the process.
Acceptance: a known breached password is rejected with an accessible
explanation; a 40-character passphrase containing spaces is accepted.
```

#### 5 · P2-RMR-1 — Crypto core

```text
Build the crypto core in packages/protocol: 32-byte CSPRNG nonces, ephemeral
X25519 key pairs, HPKE seal and open, and AES-256-GCM with a separate subkey per
direction derived by HKDF and the message index as additional authenticated
data. Use Node's own crypto wherever it has the primitive.
Acceptance: known-answer tests pass, and a message captured in one direction and
replayed in the other fails to decrypt.
```

#### 6 · P2-RMR-2 — Protocol steps 1 and 2, with channel binding

```text
Implement steps 1 and 2 server-side. On hello, generate the session key, nonce_s
and nonce_s2; produce sigma_s as an ECDSA P-256 signature over the canonical
length-prefixed encoding of nonce_u, PKEncKey_u and S_id; seal the session key to
PKEncKey_u with HPKE as c1; and store everything in the pending record.
The signature MUST cover all three fields. Signing the nonce alone is the exact
weakness Lowe identified and the attack we must defeat.
Acceptance: a captured transcript shows all three fields inside the signature,
and a unit test proves a signature over the nonce alone fails verification.
```

#### 7 · P3-RMR-1 — WebAuthn registration

```text
Implement the WebAuthn registration ceremony with SimpleWebAuthn: relying-party
ID taken from the shared S_id constant, attestation none, user verification
preferred, resident key preferred. Persist credential id, public key, signature
counter, transports and AAGUID against the authenticator record.
Acceptance: a physical key and a platform authenticator both enrol and persist
correctly, and re-registering the same credential is rejected.
```

#### 8 · P3-RMR-2 — WebAuthn assertion as protocol step 5a

```text
Implement the authentication ceremony as step 5a: the challenge IS the issued
nonce_s2, verbatim, taken from the pending record and not from the request. Check
origin and relying-party ID against S_id, reject a signature-counter regression,
and consume the replay-cache entry on success.
Acceptance: an assertion whose challenge is anything other than the issued
nonce_s2 is refused, and an assertion minted for another origin is refused.
```

#### 9 · P4-RMR-1 — OTP core

```text
Implement the OTP core: six decimal digits derived by HMAC-SHA256 over nonce_s2,
the user id and the channel name, as given in the shared context. Store only a
hash of the code, make it single use, give it the fixed 180 second lifetime, and
verify in constant time. The code must be bound to one pending record so it
cannot be presented in a different handshake.
Acceptance: one pending record never yields two valid codes; a used code dies
immediately; a code issued in one handshake is refused in another.
```

#### 10 · P4-RMR-2 — Protocol steps 4 and 5b

```text
Wire steps 4 and 5b: c3 carries nonce_s2 to the client inside the tunnel, and c4
carries the submitted code back. Invalidate the code on success, on expiry and
when the handshake is abandoned, and decrement the shared attempt counter on
every failure. zod-validate the decrypted contents of c4 before using them.
Acceptance: expiry, abandonment and success each leave the code unusable, and a
malformed c4 payload is rejected without touching the verifier.
```

### Day 2

#### 11 · P5-RMR-1 — Session lifetime and revocation

```text
Implement session lifetime rules: an idle timeout, an absolute maximum lifetime,
revocation on logout, and bulk revocation of every other session on password
change, authenticator removal or suspected compromise.
Acceptance: removing an authenticator kills every live session for that user,
proved by a test holding two sessions open.
```

#### 12 · P5-RMR-2 — Step 6 and tunnel teardown

```text
Implement step 6: the success confirmation sent inside the tunnel, key material
zeroised afterwards, and an atomic transition from pending record to session so
no window exists in which both are valid.
Acceptance: a test proves the pending record is terminal the instant the session
exists, and that the session key is no longer in memory after teardown.
```

#### 13 · P6-RMR-1 — Recovery code generation

```text
Generate recovery codes as the shared context fixes them: ten codes of ten
Crockford base32 characters, no ambiguous letters, from a CSPRNG, stored
Argon2id-hashed, single use with atomic invalidation. Grouping for reading aloud
is the front end's job, not yours, but the alphabet is yours.
Acceptance: a code submitted twice succeeds only once even under concurrent
submission.
```

#### 14 · P6-RMR-2 — Recovery flow, server side

```text
Implement account recovery: password plus one recovery code, with a cooldown
between attempts. On success, suspend the lost authenticator immediately, require
a replacement to be enrolled within the recovered session, revoke every other
session, and emit a notification event. The account must not be able to end the
flow with the lost key still usable.
Acceptance: a test proves the suspended key cannot authenticate afterwards, and
that abandoning the flow leaves the account no weaker than before.
```

#### 15 · P7-RMR-1 — Accessible Authentication conformance argument

```text
Write the conformance argument for WCAG 2.2 success criterion 3.3.8: show that no
authentication path requires a cognitive function test. Cover password manager
support, paste being allowed everywhere, FIDO2 as the route with no transcription
at all, and the OTP paths as alternatives rather than requirements. Point each
claim at the code or test that backs it.
Acceptance: the argument stands alone and every claim in it names a file or a
test.
```

#### 16 · P7-RMR-2 — Hardening against malicious assistive software

```text
Harden the client against threat T6: keep secret-bearing fields out of the
accessibility tree where the platform allows it without breaking screen-reader
use, put no secret in a DOM attribute, placeholder or title, and give clear
clipboard guidance. Then write down honestly what a compromised screen reader can
still observe, because we cannot defeat it and should not pretend to.
Acceptance: a documented residual-risk statement plus tests asserting no secret
appears in any attribute.
```

#### 17 · P8-RMR-1 — Man-in-the-middle suite with a control

```text
Using the attack harness, implement the Lowe-style substitution attack from the
design document against our server: intercept the hello, replace PKEncKey_u with
the attacker's key, and attempt to relay. Then build a deliberately weakened
server variant whose signature covers only the nonce, and run the same script
against it.
Acceptance: the attack SUCCEEDS against the weakened control and FAILS against
ours, with both transcripts captured. This pair is the centrepiece of the report.
```

#### 18 · P8-RMR-2 — Cut-and-paste and interleaving suites

```text
Implement the remaining two attack families. For cut-and-paste, run two server
instances with different S_id values and attempt to splice credential messages
from one login into the other. For interleaving, run two concurrent sessions with
the same password and a reused nonce_u and attempt to swap the final replies.
For each, state in the output which enabling condition our design removed.
Acceptance: both attacks fail, and each result names the condition and the field
that defeats it.
```

## Pathirana D.P.C.N. (DPC) — Channels

You own how a code reaches a user who cannot read a screen, and the tests that prove all three paths work. Run prompt 2 first thing on day one: if the vibration path will not work on the hardware you have, everyone needs to know before lunch.

### Day 1

#### 1 · P0-DPC-1 — Channel interface and mock

```text
Define the SecondFactorChannel interface in packages/protocol with enrol,
challenge, verify and revoke, plus the enrolment state machine each channel
shares. Ship an in-memory MockChannel implementing it, so the other four can
develop and test without a Twilio account or a phone.
Acceptance: the mock passes a conformance test suite that every real channel
will later have to pass too.
```

#### 2 · P0-DPC-2 — Spike both real channels

```text
Spike the two real channels before anything is built on them. Place one outbound
Twilio call from Node and confirm what a trial account refuses. Separately, serve
a page over HTTPS and confirm the Vibration API works on a real Android handset,
and confirm what Safari on iOS does. Write a one-page note on what each platform
will and will not do.
Acceptance: the note names every limitation found, and says plainly whether the
haptic channel needs a plan B.
```

#### 3 · P1-DPC-1 — Authenticator service

```text
Build the service layer over the authenticators table: create, list, rename and
revoke, with a factor-type enum of fido2, voice and haptic, a user-assigned
nickname, and the enrolment state machine from prompt 1. A channel address such
as a phone number is stored so it can be rendered only in masked form.
Acceptance: a factor can be added, renamed, listed and revoked through the
service, and the raw phone number is never returned by any read method.
```

#### 4 · P1-DPC-2 — Registration and password endpoints

```text
Expose the registration and password-change endpoints over the hardened server,
zod-validating every input, calling the Argon2id service and the policy check,
and emitting an audit event on every outcome including failures. Responses must
be identical whether or not the account exists.
Acceptance: integration tests cover the success and every failure path, and no
response distinguishes an unknown user from a wrong password.
```

#### 5 · P2-DPC-1 — Protocol step 3

```text
Implement step 3: decrypt c2 inside the tunnel, zod-validate the decrypted
contents, check that the nonce_s it carries matches the one this pending record
issued, then verify the password against the Argon2id hash. On success move the
record to AWAITING_SECOND_FACTOR and grant nothing else. On failure return a
generic error and decrement the shared attempt counter.
Acceptance: a correct password alone grants no access, and a c2 carrying a stale
nonce_s is rejected before the hash is even checked.
```

#### 6 · P2-DPC-2 — Redacting protocol trace logger

```text
Build a development-only protocol trace logger that records a structured
transcript of all six steps: which message, which checks ran, which passed. It
must show the shape of the exchange without ever recording a password, a session
key, an OTP or a signature's private input, and it must be impossible to enable
in production.
Acceptance: a test runs a full login and asserts no secret reaches the
transcript, and the transcript is readable enough to paste into the report.
```

#### 7 · P3-DPC-1 — Factor listing and selection

```text
Expose the endpoints that list a user's enrolled second factors and record their
choice. The list comes from the policy engine with FIDO2 ordered first and
announced as recommended. Selection writes to the pending record only; it can
never add a factor that was not offered. Switching between offered factors MUST
NOT reset the attempt counter.
Acceptance: a test switches factor three times and sees the counter keep
counting, and a request naming an unenrolled factor is refused.
```

#### 8 · P3-DPC-2 — Hardware compatibility matrix

```text
Test enrolment and authentication with at least two different physical security
keys and one platform authenticator, across the browsers we support. Record for
each: whether it enrolled, whether it authenticated, how discoverable the touch
area is by feel alone, and whether a PIN was demanded. The touch-area notes
matter as much as the pass or fail.
Acceptance: the matrix is committed and feeds the report's accessibility
findings.
```

#### 9 · P4-DPC-1 — Voice channel

```text
Implement the Twilio voice channel behind the SecondFactorChannel interface:
place an outbound call to the number verified at enrolment and read the six
digits one at a time with clear pauses, speak the code twice, and offer a DTMF
key to hear it again. The number is verified at enrolment and never displayed in
full afterwards. Keep the mock driver working for CI.
Acceptance: a real call reads a code clearly enough that a listener transcribes
it correctly first time.
```

#### 10 · P4-DPC-2 — Vibration encoding scheme

```text
Design and implement the vibration encoding, which the design document demands
but never defines. It must unambiguously convey each digit, the boundary between
digits, a repeated digit, and the start and end of the code. Use a distinct
preamble, N short pulses per digit, a clear inter-digit gap, and a long end
marker. Zero needs its own unambiguous form. Document it as a table.
Acceptance: three people who have only read the table decode a six-digit code
correctly from the device.
```

### Day 2

#### 11 · P5-DPC-1 — End-to-end tests for all three paths

```text
Write end-to-end tests that drive the real HTTP stack through a complete login
for each second factor: security key via the virtual authenticator, voice OTP
via the mock driver, haptic OTP via the companion in test mode. Each test covers
handshake, password, challenge, factor and session.
Acceptance: three green end-to-end tests running in CI on every push.
```

#### 12 · P5-DPC-2 — Session security tests

```text
Write the session attack tests: session fixation, a stolen cookie replayed after
revocation, exceeding the concurrent-session limit, and behaviour exactly at the
idle and absolute timeout boundaries.
Acceptance: each case has a named test that fails by design if the protection is
removed.
```

#### 13 · P6-DPC-1 — Adding and removing the OTP factors

```text
Build the add and remove flows for the voice and haptic factors: a phone number
must be re-verified by a call before it becomes usable, a haptic device must be
re-paired, and revocation propagates at once so a removed device stops receiving
patterns within seconds.
Acceptance: a revoked device is disconnected immediately and an unverified number
can never be used as a factor.
```

#### 14 · P6-DPC-2 — Security notifications

```text
Build the notification service for security-relevant changes: enrolment,
revocation, recovery and password change. Messages are plain text, structured for
a screen reader, say what happened and when, and tell the user what to do if it
was not them. Exactly one notice per event, never a duplicate.
Acceptance: each of the four events produces one correctly worded notice, proved
by test.
```

#### 15 · P7-DPC-1 — Low-vision sweep

```text
Audit the interface for WCAG 1.4.3 and related criteria: every colour token at
4.5:1 for text and 3:1 for interface components, usable at 200 percent zoom,
reflowing at 320 pixels with no horizontal scrolling, and honouring reduced
motion and operating-system high-contrast settings.
Acceptance: no contrast failure in the token audit and no horizontal scroll at
320 pixels on any screen.
```

#### 16 · P7-DPC-2 — Timing sweep

```text
Audit every timing behaviour against requirement R8 and WCAG 2.2.1: no hard
timeout without a warning, codes always re-requestable, time extendable, and
remaining time announced at intervals rather than counted down continuously,
which is unbearable with a screen reader.
Acceptance: a user who takes four minutes to enter a code still succeeds, and
nothing expires silently.
```

#### 17 · P8-DPC-1 — Demo recording

```text
Script and record the demonstration: a login by each of the three second factors,
a key enrolment, an account recovery, and one live attack being blocked. Record
with the screen reader audible, and narrate what is happening rather than what is
on screen.
Acceptance: the recording makes sense with the monitor switched off. That is the
whole point of this project, so test it that way before you submit it.
```

#### 18 · P8-DPC-2 — Limitations write-up

```text
Write the known-limitations section, extending the design document's own: the
dependence on server-side randomness, the dependence on correct certificate
validation, the weaker guarantees of the OTP fallback compared with the security
key, what a compromised screen reader can still see, any platform the haptic
channel does not support, and the fact that no usability study with blind
participants was run.
Acceptance: nothing anywhere in the report overclaims, and a reader can tell
exactly what was not built.
```

## Garavi W.A.I. (WAI) — Front end and accessibility

Every screen is yours, and so is the evidence the project is ultimately marked on. Test with the monitor off, not with a checklist: if you can complete a flow by ear and keyboard alone, it works.

### Day 1

#### 1 · P0-WAI-1 — App shell and announcer

```text
Build the React app shell: routing, a skip link, proper landmark regions, a
page-title update on every route change, and a single announcer service wrapping
a polite and an assertive live region that every later screen will use instead of
rolling its own.
Acceptance: a screen reader announces each route change once, and the skip link
reaches main content with one key press.
```

#### 2 · P0-WAI-2 — Accessibility tooling baseline

```text
Set up the accessibility tooling the whole team will rely on: axe-core running in
development, the jsx-a11y lint rules enabled and failing the build, a Playwright
harness with the axe integration, and a written manual checklist template for
screen-reader runs.
Acceptance: a page with a deliberately unlabelled input fails both the lint rule
and the harness.
```

#### 3 · P1-WAI-1 — Registration and login forms

```text
Build the accessible registration and login forms: every input with a real label
and a described-by hint, autocomplete set correctly so password managers work,
paste explicitly allowed, and a show/hide password control whose state is
announced when it changes. No placeholder is used as a label.
Acceptance: a screen reader reads every field and its purpose, paste works, and
the toggle announces shown or hidden.
```

#### 4 · P1-WAI-2 — Error component

```text
Build the reusable error component for WCAG 3.3.1 and 3.3.3: errors rendered
into a live region, focus moved to an error summary on submit, each entry linked
to its field, and every message saying how to fix the problem rather than only
that one exists.
Acceptance: submitting an empty form moves focus to the summary and reads every
error exactly once.
```

#### 5 · P2-WAI-1 — Client handshake module

```text
Build the client half of the handshake: generate the ephemeral key pair, send the
hello, and run the three automatic checks on the server's reply. The signature
must verify under the certified server key, the signed nonce_u must equal the one
we sent, and the signed PKEncKey_u must be byte-identical to our own key. Any
failure aborts before a password field is ever rendered. The user does nothing.
Acceptance: each check has its own unit test, and failing any one of the three
leaves the user with no password field at all.
```

#### 6 · P2-WAI-2 — Non-visual handshake feedback

```text
Build the handshake feedback: a polite announcement while the connection is being
secured, and on a binding failure an assertive message that explains the
connection could not be trusted and offers no way back into a login form. A
sighted user would see a browser warning; our user gets this instead, so it must
not be dismissible into the happy path.
Acceptance: with a tampered server reply the user is told the connection failed
and cannot reach a password field by any route.
```

#### 7 · P3-WAI-1 — Security key enrolment

```text
Build the key enrolment flow: a clearly named Register security key action, full
keyboard operation, a user-assigned nickname so several keys can be told apart, a
confirmation given both as text and announced, and instructions that explain what
the browser's own prompt will ask BEFORE it appears, because we cannot control
that prompt.
Acceptance: a blind tester enrols a key unaided from start to finish.
```

#### 8 · P3-WAI-2 — Touch-the-key screen

```text
Build the step 5 authentication screen: a clear instruction to touch the key, the
timeout announced before it is reached, a retry that does not restart the whole
login, and an unambiguous non-visual failure path. The outcome of the ceremony
must always be announced, success or failure.
Acceptance: every ceremony outcome is announced, and a timeout never leaves the
user listening to silence.
```

#### 9 · P4-WAI-1 — Code entry

```text
Build the OTP entry screen with ONE numeric input, not six separate boxes, which
are hostile to screen readers and to paste. Set inputmode numeric and the
one-time-code autocomplete, allow paste, and announce the remaining time at 120,
60 and 30 seconds rather than continuously.
Acceptance: a screen-reader user pastes a code and submits it without fighting
focus, and the time announcements do not interrupt typing.
```

#### 10 · P4-WAI-2 — Resend, replay, and the audio warning

```text
Build the Call me again and Replay vibration controls, announcing the rate-limit
state so the user knows why a control is unavailable. Then implement requirement
R5: before ANY code is spoken aloud, the user gets an explicit per-use
confirmation warning that people nearby may hear it. Audio is off by default and
the choice is never remembered silently.
Acceptance: no code is ever spoken without an explicit confirmation in that
session.
```

### Day 2

#### 11 · P5-WAI-1 — Recent activity page

```text
Build the accessible audit view: a real table with proper header semantics, each
event described in plain language rather than log jargon, filterable by date, and
readable in a sensible order by a screen reader.
Acceptance: a screen-reader user can tell from the page whether someone else has
been trying to log in as them.
```

#### 12 · P5-WAI-2 — Session expiry experience

```text
Build the session expiry experience: a warning announced before the idle timeout
with a control to extend, and an accessible re-authentication prompt that returns
the user to exactly where they were. Nobody is ever silently logged out in the
middle of a task.
Acceptance: a user warned at the timeout boundary can extend and continue with
nothing lost.
```

#### 13 · P6-WAI-1 — Recovery code presentation

```text
Build the recovery-code screen to the design document's accessibility rule: the
codes are NEVER read aloud automatically. Provide an explicit Read these aloud
control carrying a shared-space warning, a copy control and a download, both
announcing that they succeeded, and group the characters so they can be dictated
or written down without ambiguity.
Acceptance: the codes reach the user with no audio unless the user asks for it,
and copy and download both confirm audibly.
```

#### 14 · P6-WAI-2 — Recovery flow

```text
Build the account recovery experience: an entry point reachable without the lost
factor, each step announced with progress, the replacement enrolment carried out
inside the same flow, and an option to regenerate codes when the user thinks they
have been exposed.
Acceptance: a blind user recovers an account with only their password and a
recovery code, unaided.
```

#### 15 · P7-WAI-1 — Keyboard sweep

```text
Sweep every screen for WCAG 2.1.1: logical tab order, a focus indicator at 3:1
contrast, no keyboard traps anywhere including the browser prompts we hand off
to, and focus deliberately managed on every route change and dialog open and
close.
Acceptance: every flow in the system completes with the mouse physically
unplugged.
```

#### 16 · P7-WAI-2 — Semantics sweep

```text
Sweep for WCAG 1.3.1 and 2.4.6: a correct heading hierarchy with no level skipped,
labels and fieldsets and legends where they belong, descriptive names on every
control, and native elements used in place of ARIA wherever a native element
exists.
Acceptance: the accessibility tree reads as a sensible document outline on every
screen.
```

#### 17 · P8-WAI-1 — Final report

```text
Write the final report mapping the implementation back onto the design document
section by section. Every requirement R1 to R10 and every threat T1 to T8 gets a
row naming the module that implements it and the test that proves it. Include the
traceability matrix as an appendix, and state plainly what was not built.
Acceptance: every requirement in the design document has a row that points at
real code, and nothing in the report claims more than the tests show.
```

#### 18 · P8-WAI-2 — Presentation

```text
Build and rehearse the final presentation: the architecture, a walkthrough of the
six-message protocol, the attack that succeeds against the weakened build and
fails against ours, the accessibility evidence, and the limitations. Rehearse it
end to end against the clock at least once.
Acceptance: the deck is rehearsed, timed, and every claim in it is one the demo
or the tests can back on the spot.
```

## J.D.H. Jeewandara (JDH) — Security controls and verification

You wrote the threat model, so you own proving it. Your job is adversarial: every prompt here either stops an attack or demonstrates that one fails. Run prompt 17 early on day two, because Chathuranga's attack suites cannot start until your harness exists.

### Day 1

#### 1 · P0-JDH-1 — Traceability matrix and its CI check

```text
Create traceability.yaml mapping every requirement R1 to R10 and every threat T1
to T8 to the task IDs and test names that discharge them, with the rows for work
not yet done marked as open. Add a CI job that fails when any requirement or
threat has no linked test, so coverage cannot quietly rot.
Acceptance: deliberately unlinking one requirement fails the build and the output
names it.
```

#### 2 · P0-JDH-2 — CI pipeline

```text
Build the GitHub Actions pipeline: typecheck, lint, unit tests, dependency
vulnerability scanning with osv-scanner, and secret scanning with gitleaks, all
blocking a merge. Cache sensibly so a run stays under a few minutes, because a
slow pipeline in a two-day project gets bypassed.
Acceptance: a pull request containing a planted fake credential is blocked, and a
clean run finishes fast enough that nobody disables it.
```

#### 3 · P1-JDH-1 — Uniform responses and timing equalisation

```text
Make authentication failures indistinguishable. Run a dummy Argon2id verify for
an unknown user so the work done is the same either way, hold every
authentication response to a fixed minimum duration, and return byte-identical
error text and status for unknown user and wrong password.
Acceptance: a timing test over two hundred requests cannot separate the two
cases, and the responses are byte-identical.
```

#### 4 · P1-JDH-2 — Hashing tests and benchmark

```text
Write unit and property tests for the password hashing service: salts are unique
across hashes, verification is correct, tampering with any part of the encoded
hash causes failure, and the rehash-on-login path triggers only when parameters
are stale. Then benchmark verify time on the machine we will demo from, and raise
the memory cost if it is far below 500 milliseconds.
Acceptance: the benchmark number is committed to the repository and quoted in the
report instead of the design document's theoretical figure.
```

#### 5 · P2-JDH-1 — Negative tests for the handshake

```text
Write the negative tests for protocol step 2. Each of these must abort the login
before any credential is sent: a tampered sigma_s, a substituted attacker key in
place of PKEncKey_u, a replayed c1 from an earlier session, and a reply carrying
the wrong S_id. Each test asserts which specific check caught it, not merely that
something failed.
Acceptance: all four run in CI and are linked to threats T3 and T4 in
traceability.yaml.
```

#### 6 · P2-JDH-2 — Handshake abuse controls

```text
Stop the handshake being a denial-of-service lever. Rate-limit hellos per IP, cap
concurrent pending records per identity, and bound the total memory pending
records may hold. Remember that every hello costs us an HPKE operation and every
password attempt costs us 19 MiB of Argon2id, so an unauthenticated flood is
cheap for the attacker and expensive for us.
Acceptance: a flood of hellos cannot exhaust memory, and legitimate logins still
succeed while it is happening.
```

#### 7 · P3-JDH-1 — Virtual authenticator suite

```text
Build the FIDO2 test suite on Playwright's virtual authenticator so it runs
headless with no physical key: the happy path, an assertion against the wrong
relying-party ID, a cloned key detected by signature-counter regression, and a
replayed assertion.
Acceptance: all four run in CI with no hardware attached.
```

#### 8 · P3-JDH-2 — Cross-server binding test

```text
Stand up a second server instance with a different S_id and prove that an
assertion minted for the first is refused by the second, and the reverse. This is
the evidence for the cut-and-paste defence in the design document: the point is
that the possession factor cannot be moved between servers even when the user has
reused their password.
Acceptance: the test output is clear enough to paste into the report as evidence.
```

#### 9 · P4-JDH-1 — OTP abuse controls

```text
Implement the OTP rate limits from the shared context: token buckets for sending
per channel, for verifying per identity, and per IP address. Critically, the
verify counter is SHARED across channel switches, so a user cannot buy fresh
attempts by switching from voice to haptic. On lockout, explain what happened in
accessible language and give a route out rather than a dead end.
Acceptance: switching channel does not reset the counter, and a locked-out user is
told how to recover.
```

#### 10 · P4-JDH-2 — OTP security tests

```text
Write the OTP attack tests: a used code rejected, an expired code rejected, a code
from another handshake rejected, user A's code rejected for user B, brute force
bounded by the rate limit, and a log-redaction proof that no code ever reaches
logs or error objects.
Acceptance: every case is in CI and linked to threats T2 and T5.
```

### Day 2

#### 11 · P5-JDH-1 — Audit log

```text
Build the audit log service recording nine event types: handshake started,
password result, factors offered, factor selected, challenge issued, factor
result, session created, session revoked, and rate limit hit. Each row carries a
hash of the previous row so tampering is detectable, and no row carries a
password, code, token or key.
Acceptance: altering one row breaks the chain, and the verifier reports exactly
which row failed.
```

#### 12 · P5-JDH-2 — Consolidated rate-limit policy

```text
Pull every rate limit written so far into one policy module in packages/policy,
using the numbers fixed in the shared context, so no limit is hidden inside a
route handler and all of them can be reviewed on one screen.
Acceptance: every limit in the system is declared in one file, and a test asserts
the route handlers contain no limits of their own.
```

#### 13 · P6-JDH-1 — Trusted helper grant

```text
Design and build the helper mechanism for requirement R7, which the design
document requires but never designs. A user can grant a trusted helper a scoped,
time-boxed, revocable permission to assist with specific setup steps. The helper
never receives the password, an OTP, a recovery code or the ability to add an
authenticator of their own. Every helper action is audited and attributed, and
the grant expires by itself.
Acceptance: a helper can complete the permitted steps and nothing else, the grant
expires without being revoked, and every action they took is attributable.
```

#### 14 · P6-JDH-2 — Recovery abuse tests

```text
Write the recovery attack tests: recovery attempts are rate limited, a recovery
code cannot be reused, a suspended authenticator cannot authenticate afterwards,
and recovery cannot be driven by an unauthenticated request. Recovery is an
alternative way into the account, so treat it as the attacker's preferred door.
Acceptance: each case has a named test and is linked to T7 and R4.
```

#### 15 · P7-JDH-1 — WCAG conformance matrix

```text
Build the WCAG 2.2 conformance matrix: the seven criteria the design document
names, plus any others the implementation touches, each mapped to the automated
test or the recorded screen-reader walkthrough that evidences it. An empty cell
means untested, and must be reported as untested rather than left blank.
Acceptance: the matrix has no empty cells, and every claim points at a test or a
recording.
```

#### 16 · P7-JDH-2 — Accessibility and security trade-off register

```text
Write docs/tradeoffs.md extending the design document's trade-off table with
every decision actually taken in the build where accessibility and security
pulled against each other: what we chose, why, and what risk remains. Include the
ones we got wrong first and changed.
Acceptance: reviewed by the whole team, and every entry names a real decision
rather than a hypothetical one.
```

#### 17 · P8-JDH-1 — Attack harness

```text
Build the attack harness in packages/testkit: a scriptable proxy sitting between
client and server that can drop, reorder, replay, and modify any protocol
message, and can impersonate either party. Give it a small API so one script can
mount any of the four attack families. Run this prompt first thing on day two:
Chathuranga's two suites are blocked until it exists.
Acceptance: a single script can mount replay, man-in-the-middle, cut-and-paste
and interleaving attempts against a running server.
```

#### 18 · P8-JDH-2 — Replay and eavesdropping suites

```text
Using the harness, implement the replay and eavesdropping suites: replay the
hello, replay an old c2, replay an old sigma_u, and in each case assert the
specific check that rejected it, whether that is the freshness check, the replay
cache, or both. Separately, capture a full transcript of a successful login and
assert that no secret appears anywhere in clear.
Acceptance: every rejection names its cause, and the clean transcript is
committed as the evidence for threats T1 and T2.
```

## Merge order and sync points

Most prompts are independent, which is what makes two days possible. These are the ones that are not.

| Blocked prompt | Waits on | What to do while you wait |
| --- | --- | --- |
| Everyone's prompt 1 | UDK 1 and 2, the scaffold and local services | Nothing. Stop and wait; this is twenty minutes and it unblocks all five of you |
| RMR 6, protocol steps 1 and 2 | UDK 5, the pending store | Write the canonical encoder and its tests; they need nothing |
| DPC 5, protocol step 3 | RMR 6 and RMR 3 | Build against the interface with a stubbed verifier |
| WAI 5, client handshake | RMR 1 and RMR 6 | Build the three checks against fixture messages from the schema |
| RMR 8, assertion as step 5a | UDK 7, the replay cache | Finish registration; wire the cache call last |
| JDH 5, handshake negative tests | RMR 6 | Write the tests first and let them fail; that is the right order anyway |
| JDH 7, virtual authenticator suite | RMR 7 and 8 | Set up the Playwright virtual authenticator fixture |
| DPC 9 and 10, the two channels | DPC 1 and UDK 9 | Build each channel against the mock and swap the transport in |
| RMR 17 and 18, attack suites | JDH 17, the harness | This is the tightest coupling on day two. JDH runs prompt 17 first, out of order |
| DPC 17, the demo recording | UDK 17, deployment | Script the demo and rehearse it locally |
| WAI 17, the report | Everyone's traceability rows | Write every section that does not depend on results |
| JDH 15, the WCAG matrix | WAI 15 and 16, UDK 16 | Build the matrix skeleton and fill it as evidence lands |

### Four points where everyone stops

1. **Day 1, after prompt 2.** UDK's scaffold and services are merged, and DPC reads the channel spike note to the team. If the vibration path will not work on the hardware you have, decide the fallback now, not at midnight.
2. **Day 1, after prompt 6.** The handshake is merged. Everyone rebases onto it, because the protocol types touch all five tracks.
3. **End of day 1.** Integrate and test. The gate is one login working end to end with each of the three second factors. Anything unfinished is reassigned here, not tomorrow.
4. **Day 2, midpoint.** JDH's harness is merged and RMR starts the attack suites; UDK's deployment is up so DPC can record against it.

If a gate does not close, move the unfinished task to whoever is lightest rather than letting its owner fall behind alone. The split was equal at the start; keeping it equal is a decision you make at each of these four points.
