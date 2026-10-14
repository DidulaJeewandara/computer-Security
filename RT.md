# Requirements and Threats

The requirement IDs (R1–R10) and threat IDs (T1–T8) that `prompt.md` and `traceability.yaml` refer to, copied from the DeltaForce architecture and design document (section 2.5, Adversary Model, and the requirements table).

## Threats

### Generic threats

#### T1 — Passive Eavesdropper

- Listens to/observes communication without modification
- May capture passwords or OTPs without proper protection

#### T2 — Replay Attacker

- Captures valid login message or OTP and reuses it later
- Gains unauthorized access using previously intercepted credentials

#### T3 — Message Modification Attacker

- Intercepts communication and changes information before forwarding
- May redirect OTP delivery or force downgrade to weaker authentication

#### T4 — Active Man-in-the-Middle Attacker

- Intercepts, changes, or forwards messages in real time
- Can relay login information while user enters it

### Accessibility-specific threats

#### T5 — Audio Eavesdropping

- Visually impaired users receive authentication via audio
- Someone nearby can overhear OTP or sensitive information from screen reader
- Major risk in shared physical spaces (labs, offices, public areas)

#### T6 — Malicious Accessibility Software

- Screen readers have access to information entered on device
- Malicious app with accessibility permissions could read passwords and OTPs
- Compromise of assistive technology = compromise of authentication

#### T7 — Caregiver or Helper Misuse

- Visually impaired users may need help from family member or support worker
- Helper may access authentication information
- Risk of misuse or unauthorized information sharing

#### T8 — Security Problems Caused by Difficult Authentication

- If authentication is too difficult or time-consuming, users find unsafe workarounds
- Users may write down OTPs, share credentials, or disable MFA entirely
- System must be both secure AND usable for disabled users

## Requirements

| ID | Requirement | Mitigates |
| --- | --- | --- |
| R1 | All authentication traffic MUST use authenticated encryption; no credential or code sent/stored in clear | T1, T3, T4 |
| R2 | Every one-time code MUST be single-use and bound to fresh server-issued challenge; passkey MUST sign new challenge per login | T2, T3 |
| R3 | System MUST prefer origin-bound authenticator (FIDO2/WebAuthn); code-based methods MUST include anti-relay checks | T2, T4 |
| R4 | Server MUST enforce registered factor policy; second factor MUST NOT be downgraded by unauthenticated request | T3, T4 |
| R5 | Codes should not be spoken by default; provide private options (vibration, headphones, passkeys); warn before audio | T5 |
| R6 | OTP entry path MUST minimize accessibility tree exposure; use platform authenticator/secure hardware paths; mark field sensitive | T6 |
| R7 | Trusted helpers can assist without sharing main password/authentication secret; access limited and revocable | T7 |
| R8 | OTP validity windows MUST accommodate non-visual entry (longer, re-requestable); announce remaining time; degrade gracefully | T8 |
| R9 | Each account MUST have 2+ registered authenticators and backup codes in screen-reader-unambiguous format | T7, T8 |
| R10 | System MUST rate-limit per method and expose accessible, screen-reader-friendly audit log of authentication events | T2, T4, T7 |

## Threat coverage

Which requirements mitigate each threat, derived from the table above.

| Threat | Mitigated by |
| --- | --- |
| T1 | R1 |
| T2 | R2, R3, R10 |
| T3 | R1, R2, R4 |
| T4 | R1, R3, R4, R10 |
| T5 | R5 |
| T6 | R6 |
| T7 | R7, R9, R10 |
| T8 | R8, R9 |
