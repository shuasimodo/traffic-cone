//! cone-store — encrypted credential storage for Traffic Cone.
//!
//! This crate owns all database access. It is the only crate that reads
//! or writes the SQLCipher database. All other Traffic Cone crates go
//! through the [`Store`] type.
//!
//! # Encryption
//!
//! Two independent layers:
//!
//! 1. **SQLCipher** encrypts the entire database file (AES-256), keyed from
//!    the master passphrase via Argon2id.
//! 2. **Per-key AES-256-GCM** encrypts each private key blob within the
//!    database, using a key derived independently from the master passphrase
//!    with a per-key salt.
//!
//! Private key bytes exist in plaintext only transiently during a signing
//! operation. They are zeroed immediately after use via [`zeroize`].
//!
//! # Modules
//!
//! - [`db`]        — connection, schema init, migrations
//! - [`store`]     — top-level Store, unlock/lock lifecycle
//! - [`crypto`]    — key derivation, encryption/decryption, signing
//! - [`models`]    — data types: Cert, Key, SshKey, CaCert, App, Route, etc.
//! - [`import`]    — import from PFX, PEM, DER, OpenSSH formats
//! - [`export`]    — backup export, single-cert export
//! - [`integrity`] — binary hash recording and verification
//! - [`error`]     — crate error type

pub mod crypto;
pub mod db;
pub mod error;
pub mod export;
pub mod import;
pub mod integrity;
pub mod models;
pub mod store;
pub mod list;

pub use error::StoreError;
pub use store::Store;
