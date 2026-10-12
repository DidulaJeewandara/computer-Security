# Development certificates

The protocol runs inside TLS and WebAuthn only works on the exact origin `auth.deltaforce.lk`, so everyone needs real HTTPS on that name with no browser warning. We use [mkcert](https://github.com/FiloSottile/mkcert): it makes a local CA on your machine and gets your OS and browsers to trust it.

Never switch TLS verification off to get around a warning (no `rejectUnauthorized: false`, no `NODE_TLS_REJECT_UNAUTHORIZED=0`, no `curl -k`). If you see a warning, the trust setup is wrong, so fix that. A test in `apps/auth-server/src/tls.test.ts` fails the build if any of these show up in the repo.

## 1. Install mkcert

**macOS**
```sh
brew install mkcert nss
```

**Windows** (PowerShell)
```powershell
choco install mkcert    # or: scoop install mkcert
```

**Linux**
```sh
# Debian / Ubuntu
sudo apt install libnss3-tools
# then get the binary from https://github.com/FiloSottile/mkcert/releases and put it on your PATH

# Fedora
sudo dnf install nss-tools mkcert

# Arch
sudo pacman -S nss mkcert
```
`nss` / `libnss3-tools` is what lets mkcert add the CA to Firefox and Chrome on Linux.

## 2. Add the hosts entry

Point the name at your own machine.

| OS | File | Line to add |
|---|---|---|
| macOS / Linux | `/etc/hosts` | `127.0.0.1 auth.deltaforce.lk` |
| Windows | `C:\Windows\System32\drivers\etc\hosts` (edit as Administrator) | `127.0.0.1 auth.deltaforce.lk` |

macOS / Linux one-liner: `echo "127.0.0.1 auth.deltaforce.lk" | sudo tee -a /etc/hosts`

## 3. Create your CA and certificate

From the repo root:
```sh
node scripts/dev-certs.mts
```
This runs `mkcert -install` (asks for your password, it edits the trust store) and writes `keys/auth.deltaforce.lk.pem` and `keys/auth.deltaforce.lk-key.pem`. Both are gitignored. Restart your browser after the first install.

Then check it:
```sh
node scripts/dev-certs.mts serve
```
Open `https://auth.deltaforce.lk:8443` in Chrome and Firefox. You should see `ok` and a padlock, no warning.

## 4. Trusting a teammate's server

Each member has their own CA. To reach someone else's server (integration, demo), you trust their **public** root only:

1. They send you `rootCA.pem` from `$(mkcert -CAROOT)`.
2. You install it:

| OS | Command |
|---|---|
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rootCA.pem` |
| Windows | `certutil -user -addstore Root rootCA.pem` |
| Debian / Ubuntu | `sudo cp rootCA.pem /usr/local/share/ca-certificates/teammate.crt && sudo update-ca-certificates` |
| Fedora | `sudo cp rootCA.pem /etc/pki/ca-trust/source/anchors/teammate.pem && sudo update-ca-trust` |
| Arch | `sudo trust anchor --store rootCA.pem` |

Firefox keeps its own store: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.

If the teammate's machine is reached by IP (the Android phone case below), they must have issued the cert with it: `node scripts/dev-certs.mts --san 192.168.1.20`.

## 5. Android phone (haptic companion)

The Vibration API needs HTTPS, so the phone has to trust the CA too.

1. Issue the cert with the laptop's LAN IP: `node scripts/dev-certs.mts --san <laptop-ip>`.
2. Send `rootCA.pem` to the phone.
3. Settings → Security → Encryption & credentials → Install a certificate → CA certificate.
4. Browse to `https://<laptop-ip>:8443`.

Chrome on Android trusts user-installed CAs. Apps in general don't, but we only use the browser.

## Node tools

If a Node script needs to call the dev server, give it the CA, don't disable checks:
```sh
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

## Security notes

- The mkcert root can sign a certificate for **any** site your machine trusts. Never share or commit `rootCA-key.pem`. Only `rootCA.pem` is safe to hand out.
- Only install roots from teammates you've confirmed in person or on a call.
- When the module ends, run `mkcert -uninstall` and remove any teammate roots you added.

## Sign-off

Tick your row when `https://auth.deltaforce.lk:8443` loads with no warning on your machine, in your browser.

| Member | Machine / browser | Done |
|---|---|---|
| Nethsara (UDK) | | [ ] |
| Chathuranga (RMR) | | [ ] |
| Pathirana (DPC) | | [ ] |
| Garavi (WAI) | | [ ] |
| Jeewandara (JDH) | | [ ] |
