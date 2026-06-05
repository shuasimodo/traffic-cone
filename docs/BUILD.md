# Building Traffic Cone from Source

## Prerequisites

- Rust (exact version pinned in `rust-toolchain.toml` — installed automatically by rustup)
- SQLCipher development libraries: `sudo dnf install sqlcipher-devel`
- OpenSSL development libraries: `sudo dnf install openssl-devel`
- pkg-config: `sudo dnf install pkg-config`

## Build

```bash
git clone https://github.com/shuasimodo/traffic-cone
cd traffic-cone
cargo build --release
```

Binaries are written to `target/release/`:
- `target/release/cone` — CLI tool
- `target/release/coned` — daemon
- `target/release/libcone.so` — PKCS#11 module

## Install (manual)

```bash
sudo install -Dm755 target/release/cone     /usr/local/bin/cone
sudo install -Dm755 target/release/coned    /usr/local/libexec/coned
sudo install -Dm755 target/release/libcone.so /usr/local/lib64/cone/libcone.so
sudo install -Dm644 packaging/cone.module   /usr/share/p11-kit/modules/cone.module
```

## Notes

- The toolchain version is pinned in `rust-toolchain.toml` to ensure reproducible builds
- `Cargo.lock` is committed — always build with `cargo build` not `cargo build --locked` during development, but CI uses `--locked`
- Self-compiled builds will show a warning from `cone verify` since they have no Rekor transparency log entry — this is expected and not an error
