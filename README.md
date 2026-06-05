# Traffic Cone

**Encrypted credential manager for Linux — mTLS client certificates, CA trust, and SSH keys.**

Traffic Cone fills a gap that has existed in the Linux desktop for a long time: the ability to manage all of your infrastructure credentials in one encrypted store and have them automatically presented by any application — browsers, desktop apps, CLI tools, Electron apps — without configuring each one individually.

Android has a system certificate store. Windows has one. Linux does not. Traffic Cone fixes that.

---

## What It Does

**Client certificate management (mTLS)**  
Install a client certificate once. Traffic Cone presents it automatically when any application makes a connection to a server that requests one — VSCode, desktop sync clients, Electron apps, curl, browsers. Route rules let you assign specific certificates to specific applications and hosts, so credentials are never presented to the wrong destination.

**CA trust store management**  
Import a CA certificate or chain and Traffic Cone registers it with the system trust store. Self-signed SSL on local servers, corporate root CAs, internal PKI — no more manually copying `.pem` files and running `update-ca-trust`.

**SSH key management**  
SSH private keys live in the encrypted store instead of sitting unprotected in `~/.ssh/`. Traffic Cone implements the SSH agent protocol — your existing SSH workflow is unchanged, but your keys are encrypted at rest and presented only when requested.

Everything lives in one encrypted store. One restore command on a fresh machine brings everything back.

---

## How It Works

Traffic Cone has three main components:

**`libcone.so`** — a PKCS#11 module registered with p11-kit. Every major TLS stack on Linux (GnuTLS, NSS, OpenSSL 3.x) consults p11-kit for hardware tokens and smartcards. Traffic Cone registers itself the same way. Browsers, curl, VSCode, and native Linux apps all pick it up without per-app configuration.

**`coned`** — a daemon running as a systemd user service. All intelligence lives here: route resolution, application identity verification, cryptographic signing, integrity verification. Private keys never leave this process — callers receive only signatures.

**`cone`** — the CLI management tool. Import credentials, register applications, define routing rules, manage CA trust, create encrypted backups, restore on a new machine.

---

## Quickstart

### Install

```bash
sudo dnf install traffic-cone        # Fedora / RHEL
# or build from source — see docs/BUILD.md
```

### First run

```bash
cone unlock                          # set master passphrase on first run
```

### Import a client certificate

```bash
# From a PFX / PKCS#12 file
cone import --file laptop.pfx

# From separate cert and key files
cone import --cert client.crt --key client.key
```

### Import a CA certificate

```bash
cone ca add --file internal-ca.pem --label "Internal CA"
# Registered with system trust store automatically
```

### Import an SSH key

```bash
cone ssh import --file ~/.ssh/id_ed25519 --label "Primary SSH Key"
```

### Register an application and assign routes

```bash
cone app add --label "VSCode" --exe /usr/bin/code

cone route add \
  --cert "Laptop 2026" \
  --app "VSCode" \
  --host gitlab.example.com \
  --require-both
```

### Check status

```bash
cone status
# ● coned running
# ✓ integrity verified (manifest + database)
# ✓ p11-kit registered · OpenSSL configured · SSH agent active
# ✓ 2 CA certs in system trust store
# Store: unlocked · 3 certs · 2 SSH keys
```

### Restore on a new machine

```bash
sudo dnf install traffic-cone
cone restore --file backup.cone
# All certificates, CA trust, SSH keys, apps, and routes restored
```

---

## Security

Traffic Cone is built for people who use mTLS because they take security seriously — and for people who are trying to improve their security posture and deserve software that protects them without requiring them to understand every detail.

**Private keys never leave the daemon.** `libcone.so` is a thin bridge. All signing operations happen inside `coned`. Calling processes receive only signatures — never key material. Even a perfect interception of the IPC socket yields nothing useful.

**Two layers of encryption at rest.** SQLCipher (AES-256) for the entire database, plus AES-256-GCM per key within the database, each with an independently derived key via Argon2id.

**Integrity verification at every startup.** Before unlocking the store, `coned` verifies the SHA-256 hash of every Traffic Cone binary against both a signed release manifest and a record stored inside the encrypted database. Both must pass and agree with each other. A replaced or tampered binary is caught before any key material is accessed — and the user is notified clearly.

**The database as a saferoom.** The integrity records inside the encrypted database cannot be altered without the master passphrase. An attacker who replaces binaries on disk cannot update the verification record that `coned` checks against. This is the difference between a database-backed integrity check and a system file that can be overwritten.

**Application identity verification.** Applications are identified by their resolved binary path and SHA-256 hash. A route assigned to VSCode + `gitlab.example.com` will not be triggered by any other application, or by VSCode connecting to any other host.

**Rogue process protection.** Every IPC connection is verified via SO_PEERCRED (kernel-provided, unspoofable) and binary hash before a single byte of the request is read. An abstract Unix socket means there is no socket file on disk to redirect or replace.

**Honest scope.** If your kernel or firmware is compromised, no userspace security software can protect you — and Traffic Cone does not claim otherwise. Everything above that layer is covered.

See [SECURITY.md](SECURITY.md) for the full threat model.

---

## Compatibility

| TLS Stack | Applications | Integration |
|-----------|-------------|-------------|
| GnuTLS | curl, wget, most system tools | p11-kit — automatic |
| NSS | Firefox, Chromium, Chrome | p11-kit — automatic |
| OpenSSL 3.x | VSCode, most native apps | pkcs11-provider + p11-kit |
| Bundled Electron | OpenCode, similar apps | automatic or transparent proxy |
| SSH | Any SSH client | SSH agent protocol |

**OS support:** Fedora Linux (primary), RHEL / Rocky / AlmaLinux, any modern systemd-based distribution with p11-kit.

---

## Supported Import Formats

| Format | Extensions | Contents |
|--------|-----------|----------|
| PKCS#12 | `.pfx`, `.p12` | Cert + private key + optional CA chain |
| PEM bundle | `.pem` | Cert and/or key (auto-detected) |
| DER certificate | `.crt`, `.cer`, `.der` | Public cert |
| PEM private key | `.key` | Private key, optionally passphrase-protected |
| OpenSSH private key | standard OpenSSH format | SSH keypair |

---

## Enterprise Use

Traffic Cone works well for managing credentials across fleets of machines. Package your CA certificates and client certificates into a Traffic Cone backup file, distribute it as part of your provisioning workflow, and every machine is fully configured on first boot. Key rotation means pushing an updated backup — no per-machine configuration changes required.

---

## Status

Early development. Architecture and security model are defined. Implementation in progress.

- [ ] `cone-store` — encrypted storage (SQLCipher, key material, integrity table)
- [ ] `coned` — daemon, IPC, routing, process monitor, SSH agent, startup verification
- [ ] `libcone.so` — PKCS#11 module
- [ ] `cone-cli` — management CLI
- [ ] CA trust store integration
- [ ] RPM packaging (Fedora / RHEL)
- [ ] Sigstore / reproducible build CI
- [ ] `cone-gui` — GTK4 frontend *(planned)*
- [ ] Electron transparent proxy *(planned)*

---

## Contributing

Contributions are welcome. Please read [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) before submitting changes that touch the core store or daemon.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
