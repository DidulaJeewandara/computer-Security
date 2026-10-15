# Implementation Decisions

## Breached-password list (P1-RMR-2)

- Source: NCSC "100k most used passwords", from Pwned Passwords, as published in SecLists (`Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`, MIT).
- Committed as uppercase SHA-1 hashes only, in `apps/auth-server/data/breached-passwords.sha1.txt`. No plaintext is stored.
- Entries under 8 characters are dropped because the length rule already rejects them. Both the raw and the NFKC form of each entry are hashed.
- The lookup follows the Pwned Passwords range model: only the 5-character hash prefix is used to find candidates, and the suffix is compared in process.
- To regenerate or swap in a larger list (`HASH` or `HASH:COUNT` lines also load): `node scripts/build-breach-list.ts <plaintext.txt> apps/auth-server/data/breached-passwords.sha1.txt`.
- Passwords are normalised to NFKC before the policy check and before hashing, so one password typed two ways is the same password.

## Crypto core (P2-RMR-1)

- Everything uses WebCrypto (`globalThis.crypto.subtle`), which is Node's own crypto and also runs in the browser, so `packages/protocol` stays free of `Buffer` and `node:` imports. X25519 needs Node 20+ and a current browser (Chrome 133, Firefox 129, Safari 17).
- Neither Node nor WebCrypto has HPKE, so base mode single-shot (RFC 9180) is built on HMAC, X25519 and AES-GCM for our one suite only. It is checked against the official test vector.
- Enc_key subkeys come from HKDF-SHA256 with an empty salt and the labels `deltaforce/v1 enc_key client-to-server` and `deltaforce/v1 enc_key server-to-client`. The message number selects the key: 3 and 5 go client to server, 4 and 6 server to client.
- AAD is the message number as a 4-byte big-endian integer.
- The AES-GCM IV is 12 random bytes per message rather than derived from the message number, because step 5 can be retried under the same key and number.
- An all-zero X25519 result is rejected, so a low-order public key cannot force a known shared secret.
