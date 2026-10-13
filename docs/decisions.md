# Implementation Decisions

## Breached-password list (P1-RMR-2)

- Source: NCSC "100k most used passwords", from Pwned Passwords, as published in SecLists (`Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`, MIT).
- Committed as uppercase SHA-1 hashes only, in `apps/auth-server/data/breached-passwords.sha1.txt`. No plaintext is stored.
- Entries under 8 characters are dropped because the length rule already rejects them. Both the raw and the NFKC form of each entry are hashed.
- The lookup follows the Pwned Passwords range model: only the 5-character hash prefix is used to find candidates, and the suffix is compared in process.
- To regenerate or swap in a larger list (`HASH` or `HASH:COUNT` lines also load): `node scripts/build-breach-list.ts <plaintext.txt> apps/auth-server/data/breached-passwords.sha1.txt`.
- Passwords are normalised to NFKC before the policy check and before hashing, so one password typed two ways is the same password.
