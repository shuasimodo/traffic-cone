# Architecture

Traffic Cone is a system-level credential manager for Linux. It manages mTLS client certificates, CA trust anchors, and SSH keys in a single encrypted store, presenting them automatically to any application through standard Linux interfaces — PKCS#11 via p11-kit for TLS, and the SSH agent protocol for SSH.

---

## The Problem

On Linux, infrastructure credentials are fragmented:

- Client certificates must be configured per-application, and most desktop applications have no mechanism to use them
- CA certificates must be manually installed into the system trust store via the command line
- SSH private keys sit unencrypted in `~/.ssh/`
- After a machine wipe, everything must be rebuilt from scratch

Traffic Cone solves all of this at the right layer — not with workarounds, but by integrating with the infrastructure Linux already provides for exactly this purpose.

---

## High-Level Design

```
┌──────────────────────────────────────────────────────────────────────┐
│                          User Applications                           │
│         VSCode · OpenCode · Nextcloud · curl · Firefox · ssh         │
└──────────────┬───────────────────────────────────────┬───────────────┘
               │ TLS (CertificateRequest)               │ SSH auth
┌──────────────▼──────────────────┐     ┌──────────────▼──────────────┐
│           TLS Stacks            │     │          SSH Clients         │
│  GnuTLS · NSS · OpenSSL 3.x    │     │  ssh · git · rsync · scp    │
│     (routed via p11-kit)        │     │  (via $SSH_AUTH_SOCK)        │
└──────────────┬──────────────────┘     └──────────────┬──────────────┘
               │ PKCS#11 C ABI                          │ SSH agent protocol
┌──────────────▼──────────────────┐     ┌──────────────▼──────────────┐
│          libcone.so             │     │      SSH agent socket        │
│   PKCS#11 module — thin IPC     │     │       (served by coned)      │
└──────────────┬──────────────────┘     └──────────────┬──────────────┘
               │                                        │
               │    Abstract Unix socket (IPC)          │
               │    SO_PEERCRED + binary hash auth       │
               │    Session HMAC on all messages         │
┌──────────────▼────────────────────────────────────────▼──────────────┐
│                               coned                                  │
│                       Daemon — core intelligence                     │
│                                                                      │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────────────┐   │
│  │  Route Resolver │  │ Process Mon  │  │     Crypto Core       │   │
│  │                 │  │              │  │                       │   │
│  │ app + url→cert  │  │ PID → exe    │  │ Sign (TLS + SSH)      │   │
│  │ priority rules  │  │ exe → hash   │  │ Keys: load, use, zero │   │
│  │ require_both    │  │ connections  │  │ mlock'd pages         │   │
│  └────────┬────────┘  └──────────────┘  └───────────────────────┘   │
│           │                                                          │
│  ┌────────▼─────────────────────────────────────────────────────┐   │
│  │                        cone-store                            │   │
│  │               SQLCipher — encrypted at rest                  │   │
│  │  certs · keys · ssh_keys · ca_certs · routes · apps          │   │
│  │  integrity · audit_log                                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ CA certs only
               ┌───────────────▼───────────────────┐
               │       System Trust Store           │
               │  /etc/pki/ca-trust/source/anchors/ │
               │  + update-ca-trust (via polkit)    │
               └───────────────────────────────────-┘
```

---

## Components

### libcone.so — PKCS#11 Module

A shared library registered with p11-kit. Intentionally minimal — its only job is to be a spec-compliant PKCS#11 implementation that forwards all meaningful operations to `coned` over an abstract Unix socket.

**What it does:**
- Implements the ~15 PKCS#11 functions required for client certificate auth
- All other PKCS#11 functions return `CKR_FUNCTION_NOT_SUPPORTED` (spec-compliant)
- Connects to `coned` via abstract Unix socket
- Passes SO_PEERCRED verification and binary hash check on connect
- Participates in mutual challenge-response with `coned`
- Sends signing requests, receives signatures — never key material

**What it does not do:**
- Hold private key material
- Make routing decisions
- Access the database directly

**p11-kit registration** (installed by RPM):
```ini
# /usr/share/p11-kit/modules/cone.module
module: /usr/lib64/cone/libcone.so
managed: yes
```

**OpenSSL 3.x** (configured by RPM):
```ini
# appended to /etc/ssl/openssl.cnf
[openssl_init]
providers = provider_sect

[provider_sect]
pkcs11 = pkcs11_sect

[pkcs11_sect]
module = /usr/lib64/pkcs11-provider.so
pkcs11-module = /usr/lib64/cone/libcone.so
```

---

### coned — The Daemon

A systemd user service. Starts on login, runs until logout. All intelligence, all sensitive operations, and all key material live here exclusively.

#### Startup sequence

Before accepting any connections or unlocking the store, `coned` runs its full verification sequence:

```
1. Check process environment — refuse if LD_PRELOAD / LD_AUDIT are set
2. Recompute SHA-256 of self, libcone.so, cone CLI
3. Verify against signed release manifest (/var/lib/cone/manifest.sig)
   → signature verified against public key compiled into binary at build time
4. Verify against database integrity table
   → requires master passphrase unlock
   → hashes must match manifest AND database record
   → divergence between the two is itself a tampering indicator
5. If any check fails: notify user, write audit entry, exit without touching store
6. prctl(PR_SET_DUMPABLE, 0)   — disable ptrace and core dumps
7. mlock() all key material pages — prevent swapping
8. Begin accepting IPC connections
```

#### IPC server

Listens on an abstract Unix socket (kernel namespace, no file on disk). On every new connection:

```
1. SO_PEERCRED → kernel-provided PID, UID, GID (cannot be spoofed)
2. UID must match daemon's UID
3. /proc/PID/exe → resolve binary path
4. SHA-256 binary → compare against stored hash for libcone.so or cone CLI
5. Reject immediately if hash doesn't match — connection closed, no request read
6. Mutual challenge-response: both sides sign a nonce with session keys
7. Deliver session HMAC key to verified client
8. All subsequent messages verified with session HMAC before processing
```

#### SSH agent server

Second abstract socket, path delivered via `$SSH_AUTH_SOCK` in the systemd user environment. Implements the OpenSSH agent protocol. SSH clients connect and Traffic Cone responds to key listing and signing requests exactly as `ssh-agent` would. SSH key routing follows the same logic as TLS routing.

#### Route resolver

Given a calling PID and connection context, determines which credential to present. See Routing Logic section.

#### Process monitor

Resolves PIDs to verified binary paths and hashes. Caches PID → binary mappings for process lifetime. Detects PID reuse via process start time from `/proc/PID/stat`.

#### Crypto core

All signing operations for TLS and SSH. Key material is loaded from the store, used for one operation, and zeroed immediately. Plaintext key material never leaves this component.

#### CA trust manager

Writes CA certs to `/etc/pki/ca-trust/source/anchors/cone-<label>.pem` and invokes `update-ca-trust`. Requires a polkit rule (installed by RPM) scoped to this specific directory and command only — `coned` does not run as root.

---

### cone-store — Storage Layer

The library crate shared by `coned` and `cone` CLI. Owns all database access.

**Database:** SQLCipher — AES-256 page-level encryption, keyed from master passphrase via Argon2id.

**Schema:**

```sql
-- TLS client certificates (public material)
CREATE TABLE certs (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    cert_der     BLOB NOT NULL,
    fingerprint  TEXT NOT NULL UNIQUE,
    subject      TEXT NOT NULL,
    issuer       TEXT NOT NULL,
    not_before   INTEGER NOT NULL,
    not_after    INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);

-- Private keys for TLS certs
CREATE TABLE keys (
    id           TEXT PRIMARY KEY,
    cert_id      TEXT NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    algorithm    TEXT NOT NULL,      -- RSA2048, RSA4096, EC_P256, EC_P384
    key_enc      BLOB NOT NULL,      -- AES-256-GCM ciphertext
    key_salt     BLOB NOT NULL,      -- Argon2id salt (per-key)
    key_nonce    BLOB NOT NULL       -- GCM nonce
);

-- SSH keypairs
CREATE TABLE ssh_keys (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    public_key   TEXT NOT NULL,      -- OpenSSH wire format
    key_enc      BLOB NOT NULL,
    key_salt     BLOB NOT NULL,
    key_nonce    BLOB NOT NULL,
    algorithm    TEXT NOT NULL,      -- ed25519, ecdsa-p256, rsa4096
    created_at   INTEGER NOT NULL
);

-- CA trust anchors
CREATE TABLE ca_certs (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    cert_pem     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL UNIQUE,
    subject      TEXT NOT NULL,
    not_after    INTEGER NOT NULL,
    system_file  TEXT,               -- path written under ca-trust anchors
    created_at   INTEGER NOT NULL
);

-- Registered applications
CREATE TABLE apps (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    exe_path     TEXT NOT NULL UNIQUE,
    exe_hash     TEXT NOT NULL,      -- SHA-256 at registration time
    registered_at INTEGER NOT NULL
);

-- TLS routing rules
CREATE TABLE routes (
    id           TEXT PRIMARY KEY,
    cert_id      TEXT NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
    app_id       TEXT REFERENCES apps(id) ON DELETE SET NULL,
    match_type   TEXT NOT NULL,      -- hostname, ip, ip_cidr
    pattern      TEXT,               -- null = any host
    require_both INTEGER NOT NULL DEFAULT 0,
    priority     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);

-- SSH routing rules
CREATE TABLE ssh_routes (
    id           TEXT PRIMARY KEY,
    ssh_key_id   TEXT NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
    app_id       TEXT REFERENCES apps(id) ON DELETE SET NULL,
    host_pattern TEXT,               -- null = all hosts
    created_at   INTEGER NOT NULL
);

-- Binary integrity records (AIDE-style, protected by SQLCipher)
CREATE TABLE integrity (
    id           TEXT PRIMARY KEY,
    component    TEXT NOT NULL,      -- 'coned', 'libcone.so', 'cone'
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    version      TEXT NOT NULL,
    recorded_at  INTEGER NOT NULL,
    verified_at  INTEGER
);

-- Audit log
CREATE TABLE audit_log (
    id           TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    cert_id      TEXT,
    ssh_key_id   TEXT,
    app_id       TEXT,
    detail       TEXT,
    occurred_at  INTEGER NOT NULL
);
```

---

### cone — CLI Management Tool

Communicates with `coned` over the IPC socket for live operations. Accesses the database directly for offline operations (backup, restore, import when daemon is not running).

```
# Store
cone unlock                           # prompt for master passphrase
cone lock                             # lock immediately
cone status                           # daemon state, counts, integration health
cone audit                            # recent audit log

# TLS client certificates
cone import --file <path>             # PFX/P12/PEM — auto-detected
cone import --cert <f> --key <f>      # explicit cert + key pair
cone list
cone show --label <label>
cone remove --label <label>
cone export --label <label>

# CA trust
cone ca add --file <path> --label <name>
cone ca list
cone ca remove --label <name>

# SSH keys
cone ssh import --file <path> --label <name>
cone ssh list
cone ssh remove --label <name>

# Applications
cone app add --label <name> --exe <path>
cone app list
cone app verify --label <name>        # check binary hash against stored
cone app update --label <name>        # re-register hash after app update
cone app remove --label <name>

# TLS routes
cone route add --cert <label> [--app <name>] [--host <hostname>] [--ip <addr>] [--require-both]
cone route list
cone route remove --id <id>

# SSH routes
cone ssh route add --key <label> [--app <name>] [--host <pattern>]
cone ssh route list
cone ssh route remove --id <id>

# Backup / restore
cone backup --out <file>              # encrypted export (age)
cone restore --file <file>            # import from backup

# Diagnostics
cone test --host <hostname>           # simulate TLS CertificateRequest
cone test ssh --host <hostname>       # simulate SSH auth
cone verify                           # manually trigger integrity check
```

---

## Import Design

All imported key material is re-encrypted under the master passphrase. Original file passphrases are used only at import time and never stored.

**Auto-detection:**

```
.pfx / .p12
  → PKCS#12: prompt for file passphrase, unpack cert + key + optional chain
  → offer to import any bundled CA chain into ca_certs

.pem (inspect headers)
  → CERTIFICATE + PRIVATE KEY blocks present → cert + key pair
  → CERTIFICATE only → cert only, require --key or warn
  → PRIVATE KEY only → key only, require --cert or warn

.crt / .cer / .der
  → public cert only, DER or PEM, require --key or warn

.key
  → private key, prompt for passphrase if encrypted, require --cert

OpenSSH private key
  → cone ssh import, prompt for passphrase if encrypted
```

---

## Routing Logic

```
Signing request arrives from verified IPC client with calling PID

1. Resolve /proc/PID/exe → real binary path
2. SHA-256 binary → compare against stored app hash
   → mismatch: REJECT (binary changed since registration)
3. /proc/PID/net/tcp + tcp6 → active remote endpoints
4. Resolve IPs to configured hostnames via routing table
5. Collect candidate routes: app match AND/OR host match
6. If require_both: discard any route that matches only one condition
7. Sort: priority DESC, then specificity (app+host > app > host)
8. Return highest match, or reject if none

Route resolution is independent of what the PKCS#11 caller claims.
Object handles cannot be used to request certs the caller is not routed to.
```

---

## TLS Stack Integration

| Stack | Applications | Integration |
|-------|-------------|-------------|
| GnuTLS | curl, wget, system tools | p11-kit native — automatic |
| NSS | Firefox, Chromium, Chrome | p11-kit native — automatic |
| OpenSSL 3.x | VSCode, most native apps | pkcs11-provider + p11-kit — RPM configures |
| Bundled Electron | OpenCode, similar | Path A: system NSS (automatic) or Path B: transparent localhost proxy |

**Electron Path B:** When an Electron app bundles Chromium and ignores system NSS, `coned` can run a minimal HTTPS proxy bound to `127.0.0.1` for that specific application. The app is configured once to use the local address. All routing logic and key material stay in `coned`. Routing rules are configured identically regardless of path. `cone test` determines which path applies for a given app.

---

## Post-Wipe Recovery

```bash
sudo dnf install traffic-cone
cone restore --file backup.cone
# Enter master passphrase: ••••••••••••
# Enter backup passphrase: ••••••••••••
# Restored: 3 client certs · 2 CA certs · 2 SSH keys · 4 apps · 9 routes

cone status
# ● coned running
# ✓ integrity verified (manifest + database)
# ✓ p11-kit module registered
# ✓ OpenSSL provider configured
# ✓ SSH agent active ($SSH_AUTH_SOCK)
# ✓ 2 CA certs in system trust store
# Store: unlocked
```

---

## Project Structure

```
traffic-cone/
├── crates/
│   ├── cone-store/        # SQLCipher storage, key material, import/export
│   ├── coned/             # Daemon: IPC, routing, process monitor, SSH agent, integrity
│   ├── cone-p11/          # PKCS#11 .so — thin IPC bridge
│   └── cone-cli/          # cone binary
├── crates-later/
│   └── cone-gui/          # GTK4 frontend (planned)
├── packaging/
│   ├── cone.spec          # RPM spec
│   ├── cone.module        # p11-kit registration
│   ├── coned.service      # systemd user service
│   ├── cone-ca.rules      # polkit rules for ca-trust writes
│   └── cone.pub           # project release public key (compiled into coned)
├── docs/
│   └── BUILD.md
├── .github/
│   └── workflows/
│       └── release.yml    # reproducible build + Sigstore signing
├── rust-toolchain.toml    # pinned toolchain for reproducible builds
├── Cargo.toml             # workspace
├── ARCHITECTURE.md
├── SECURITY.md
└── README.md
```

---

## Technology Stack

| Crate | Key Dependencies |
|-------|-----------------|
| cone-store | `rusqlite` + sqlcipher feature, `argon2`, `aes-gcm`, `pkcs12`, `pkcs8`, `sha2` |
| coned | `tokio`, `ssh-agent-lib`, `p256`, `rsa`, `nix` (prctl/mlock), `zeroize` |
| cone-p11 | `cryptoki` |
| cone-cli | `clap`, `dialoguer`, `zeroize` |
| cone-gui | `gtk4-rs` (planned) |

All crates in a single Cargo workspace. All security-critical crates use `zeroize` to ensure key material is cleared from memory. Implementation language: Rust.

### Build reproducibility

`rust-toolchain.toml` pins the exact Rust toolchain version. `Cargo.lock` is committed and all dependency hashes are verified. CI builds use a locked container image. The same source always produces the same binary hash.
