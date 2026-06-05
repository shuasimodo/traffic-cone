# Security Model

Traffic Cone stores private key material that people trust to secure their infrastructure. That trust carries a real responsibility — especially for users who are trying to improve their security posture but may not have the expertise to detect a compromise on their own. This document defines exactly what Traffic Cone protects against, how it does so, what it cannot protect against, and why.

---

## Design Philosophy

The central principle of Traffic Cone's security model is: **private keys never leave the daemon.**

`coned` is the only process that ever holds plaintext key material, and only transiently during a signing operation. Everything else — `libcone.so`, `cone` CLI, calling applications like VSCode or curl — receives only signatures and public certificate material. Even a perfect interception of every byte on the IPC socket yields nothing useful to an attacker. There are no keys to steal in transit, because keys are never in transit.

Everything else in this document is defense in depth around that core guarantee.

---

## Threat Model

### What we protect against

---

**Credential theft from disk**

Private key material is never stored in plaintext. The SQLCipher database is AES-256 encrypted at the file level, keyed from the master passphrase via Argon2id. Key material within the database receives a second independent layer of AES-256-GCM encryption with a per-key derived key. An attacker with a copy of the database file and no passphrase learns nothing — not even metadata about what keys are stored.

---

**Key material interception on the IPC socket**

The Unix socket between `libcone.so` and `coned` never carries private key bytes. Signing operations happen inside `coned`. The socket carries signing requests and signatures only. An attacker who intercepts every message on the socket learns what certificates are being used and when — not the keys themselves. Private keys cannot be reconstructed from signatures.

---

**Rogue process connecting to the daemon**

This is a realistic threat. Any software running as your user — including a compromised npm package, a malicious VSCode extension, or any process that obtained user-level execution — could attempt to connect to `coned`'s socket and request signing operations.

Traffic Cone defends against this at the socket level before any request is processed:

- **Abstract Unix socket**: the daemon socket is an abstract Unix socket (Linux kernel namespace, prefixed with a null byte). There is no socket file on disk to redirect, replace, or bind over. It cannot be tampered with from userspace.
- **SO_PEERCRED**: on every new connection, `coned` immediately reads the kernel-provided peer credentials — PID, UID, GID. This is provided by the kernel and cannot be spoofed by the connecting process.
- **Binary hash verification**: `coned` resolves the connecting PID's binary via `/proc/PID/exe` and computes its SHA-256 hash. Only `libcone.so` and `cone` CLI are permitted clients, and only if their hashes match the values recorded at install time. Any other process — including a modified version of Traffic Cone's own binaries — is rejected before a single byte of the request is read.

---

**Socket-level MITM or message tampering**

Even with a legitimate connection established, message integrity is enforced via a session HMAC key. On startup, `coned` generates a 256-bit random session key in memory — never written to disk. After a connection passes the SO_PEERCRED and binary hash checks, `coned` delivers the session key to the verified client over the now-authenticated connection. Every subsequent message is HMAC'd with this key. A tampered message is rejected before processing.

Both sides verify each other. `libcone.so` confirms it is connected to the real `coned` via a startup challenge-response. `coned` confirms the caller is a verified Traffic Cone binary. Neither side proceeds without the other passing.

---

**Memory inspection of the daemon**

At startup, `coned` calls `prctl(PR_SET_DUMPABLE, 0)`. This prevents any process — including root-owned processes that dropped back to user level — from attaching a debugger via `ptrace` or triggering a core dump of `coned`'s memory. Combined with `mlock()` on all pages holding key material (preventing swap), the window for extracting key bytes from a running daemon is extremely narrow.

---

**LD_PRELOAD injection into the daemon**

A process or library installed with root access could attempt to inject a malicious shared library into `coned` via `LD_PRELOAD` or by patching the dynamic linker. `coned` inspects its own process environment at startup and refuses to run if `LD_PRELOAD`, `LD_AUDIT`, or similar dynamic linker override variables are set. The startup check is performed before the store is unlocked.

Note: LD_PRELOAD injection into *calling applications* (VSCode, curl, etc.) is a concern for those applications, not for Traffic Cone. A hook into VSCode's OpenSSL could intercept TLS session data — but still cannot reach keys stored in `coned`. The signing-only model is the protection here.

---

**Binary replacement after install**

An attacker with filesystem access could replace `coned`, `libcone.so`, or `cone` with malicious versions. Traffic Cone implements a two-layer integrity verification system that catches this before any keys are touched.

**Layer 1 — Signed release manifest** (`/var/lib/cone/manifest.sig`):  
Written at install time by the RPM. Contains the SHA-256 hash of every Traffic Cone binary, signed with the project's release key. The project's public key is compiled into `coned` at build time. On startup, `coned` recomputes hashes of all its binaries and verifies them against the manifest signature. A replaced binary produces a hash mismatch. A replaced manifest fails the signature check. Both must pass.

**Layer 2 — Database integrity table**:  
At install time, the same hashes are written into the encrypted SQLCipher database. This table cannot be altered without the master passphrase. An attacker who replaces binaries and somehow forges the manifest signature still cannot update the database record without knowing the user's passphrase. On startup, `coned` checks both layers — and both must agree with each other. Divergence between the manifest and database records is itself treated as a tampering indicator.

If verification fails at either layer: `coned` refuses to start, does not touch the store, and surfaces a clear notification to the user. The audit log records the failure with a timestamp.

The database integrity layer is analogous to AIDE (Advanced Intrusion Detection Environment) — a known-good state recorded at install time, checked silently at every startup, with the added property that the record itself is cryptographically protected by the user's passphrase.

---

**Unofficial or tampered builds distributed as official**

Release binaries are signed via Sigstore and logged to the Rekor public transparency ledger. Every official build is tied to a specific GitHub Actions run and a specific commit. The log is append-only and public — a tampered or fraudulent build would produce a log entry that doesn't match the source commit, and would be visible to anyone inspecting the log. Traffic Cone builds are reproducible: the same source always produces the same binary hash, so anyone can independently verify a release.

When network is available, `coned` optionally checks the installed version's hash against Rekor. Configurable as warn-only (default) or block. A binary with no Rekor entry — meaning it did not come from an official CI build — produces a clear warning. Self-compiled builds are a legitimate use case; Traffic Cone does not block them, but it distinguishes them from verified releases.

---

**Credentials presented to the wrong destination**

Routing rules can require both an application match and a host/IP match. A certificate assigned to VSCode + `gitlab.example.com` is not presented by any other application, and not presented by VSCode to any other host. Application identity is verified via `/proc/PID/exe` binary hash on every request. Both conditions must be satisfied simultaneously when `require_both` is set on a route.

---

### What we do not protect against

**Compromised kernel or firmware**

If an attacker controls the kernel — through a kernel exploit, a malicious kernel module, or compromised firmware — they control the environment that all of Traffic Cone's defenses run in. `PR_SET_DUMPABLE`, `mlock()`, socket permissions, and binary hash checks are all kernel features. A kernel-level attacker can bypass or lie about all of them.

This is explicitly out of scope, and it is the honest limit of any userspace security software. Full disk encryption and secure boot are the mitigations for this threat, and they operate at a level below Traffic Cone.

**A fully compromised user session**

If an attacker has arbitrary code execution as your user and has been present long enough to observe a `coned` process before `PR_SET_DUMPABLE` was set, or to inject into a process before it loads `libcone.so`, the window exists for exploitation. Traffic Cone minimises this window but does not eliminate it. This is the same limitation as `ssh-agent`, `gpg-agent`, and every other credential manager.

**Supply chain compromise before signing**

If a malicious dependency or build system compromise produces a tampered binary that passes through CI and gets officially signed, that binary will have a valid Rekor entry and valid RPM signature. This is the fundamental limit of any code signing system. The mitigations are: reproducible builds (so the community can independently verify), dependency pinning with hash verification in `Cargo.lock`, and minimal dependencies in security-critical crates.

---

## Key Storage

### Encryption layers

```
SQLCipher database file
└── AES-256 page-level encryption
    └── Key: Argon2id(master_passphrase, db_salt)
        parameters: memory ≥ 64MB, iterations ≥ 3, parallelism = 1

    keys / ssh_keys rows
    └── key_enc: AES-256-GCM
        └── Key: Argon2id(master_passphrase, per_key_salt)
            with independent salt per key
```

### Master passphrase

- Never stored anywhere — not on disk, not in the database
- Argon2id parameters are stored in the database header and can be increased over time
- The derived database key is held in `mlock()`'d memory for the duration of the unlocked session
- Zeroed on daemon shutdown, `cone lock`, or idle timeout
- Unlock attempts are rate-limited with exponential backoff

### Signing operations

Key material exists in plaintext memory for the minimum time required to complete one signing operation:

1. Route resolution determines which key applies (or rejects the request entirely)
2. Encrypted key blob is loaded from the database into locked memory
3. Signing operation is performed
4. Plaintext key is immediately zeroed
5. Only the signature is returned to the caller

---

## Integrity Verification

### Database integrity table

```sql
CREATE TABLE integrity (
    id            TEXT PRIMARY KEY,
    component     TEXT NOT NULL,     -- 'coned', 'libcone.so', 'cone'
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,     -- hash recorded at install or last verified upgrade
    version       TEXT NOT NULL,
    recorded_at   INTEGER NOT NULL,
    verified_at   INTEGER            -- timestamp of last successful startup check
);
```

Written at install time. Updated only by a `coned` process that has already passed full verification — meaning an attacker cannot update these records without first running a clean, verified `coned`, which requires the master passphrase and passing binary verification. The table is protected by SQLCipher like all other data.

### Startup verification sequence

```
coned starts
  → check process environment for LD_PRELOAD / LD_AUDIT → refuse if set
  → recompute SHA-256 of self, libcone.so, cone CLI
  → verify against signed release manifest (/var/lib/cone/manifest.sig)
      → signature check against compiled-in public key
      → hash comparison
  → verify against database integrity table
      → requires passphrase to read
      → hash comparison
  → both layers must pass AND agree with each other
  → if any check fails:
      → do not unlock store
      → write failure to audit log
      → notify user with clear message
      → exit
  → set PR_SET_DUMPABLE 0
  → mlock key material pages
  → begin accepting connections
```

---

## Backup Security

Backup files use `age` encryption (ChaCha20-Poly1305):

- **Passphrase mode**: scrypt key derivation, independent from runtime master passphrase
- **Public key mode**: X25519 recipient, for automated backup workflows

Both passphrases are required to use extracted key material: the backup passphrase decrypts the backup file, but key blobs inside are still encrypted under the master passphrase. Compromising one passphrase does not compromise the other.

Backup files do not contain the master passphrase, any derived key, or plaintext key material at any point during export.

---

## Honest Summary

Traffic Cone protects your private keys against:
- Theft from disk
- Interception on the IPC channel
- Rogue processes requesting signing operations
- Binary replacement and tampered installs
- Unofficial or tampered builds

Traffic Cone cannot protect against:
- A compromised kernel or firmware (use full disk encryption and secure boot)
- A fully compromised user session where the attacker predates `coned`'s startup hardening

For users who install Traffic Cone to improve their security posture: the realistic threats — a compromised npm package, a malicious VSCode extension, software installed with sudo that wasn't what it claimed to be — are all covered. Your keys do not leave the daemon. The daemon verifies its own integrity before touching them. If something is wrong, you are told before any key material is accessed.
