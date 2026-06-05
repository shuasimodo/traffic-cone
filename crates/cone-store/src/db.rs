//! Database connection and schema management.
//!
//! Opens the SQLCipher database, applies the master passphrase,
//! and ensures the schema is up to date.

use rusqlite::{Connection, params};
use crate::error::StoreError;

/// Open the SQLCipher database at `path` with the given key.
/// Creates the file and initialises the schema if it does not exist.
pub fn open(path: &str, key: &str) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)?;

    // Apply SQLCipher key — this must happen before any other statement
    conn.execute_batch(&format!("PRAGMA key = '{}';", key))?;

    // Verify the key is correct by reading the schema version
    // If the key is wrong, SQLCipher returns an error here
    conn.execute_batch("PRAGMA schema_version;")?;

    // Enforce WAL mode and foreign key constraints
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        PRAGMA secure_delete = ON;
    ")?;

    migrate(&conn)?;

    Ok(conn)
}

/// Apply schema migrations in order.
/// Each migration is idempotent — safe to run on an existing database.
fn migrate(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );

        INSERT INTO schema_version (version)
        SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
    ")?;

    let version: i64 = conn.query_row(
        "SELECT version FROM schema_version",
        [],
        |row| row.get(0),
    )?;

    if version < 1 {
        migration_001(conn)?;
        conn.execute("UPDATE schema_version SET version = 1", [])?;
    }

    Ok(())
}

fn migration_001(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS certs (
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

        CREATE TABLE IF NOT EXISTS keys (
            id           TEXT PRIMARY KEY,
            cert_id      TEXT NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
            algorithm    TEXT NOT NULL,
            key_enc      BLOB NOT NULL,
            key_salt     BLOB NOT NULL,
            key_nonce    BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ssh_keys (
            id           TEXT PRIMARY KEY,
            label        TEXT NOT NULL,
            public_key   TEXT NOT NULL,
            algorithm    TEXT NOT NULL,
            key_enc      BLOB NOT NULL,
            key_salt     BLOB NOT NULL,
            key_nonce    BLOB NOT NULL,
            created_at   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ca_certs (
            id           TEXT PRIMARY KEY,
            label        TEXT NOT NULL,
            cert_pem     TEXT NOT NULL,
            fingerprint  TEXT NOT NULL UNIQUE,
            subject      TEXT NOT NULL,
            not_after    INTEGER NOT NULL,
            system_file  TEXT,
            created_at   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS apps (
            id            TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            exe_path      TEXT NOT NULL UNIQUE,
            exe_hash      TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS routes (
            id           TEXT PRIMARY KEY,
            cert_id      TEXT NOT NULL REFERENCES certs(id) ON DELETE CASCADE,
            app_id       TEXT REFERENCES apps(id) ON DELETE SET NULL,
            match_type   TEXT NOT NULL,
            pattern      TEXT,
            require_both INTEGER NOT NULL DEFAULT 0,
            priority     INTEGER NOT NULL DEFAULT 0,
            created_at   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ssh_routes (
            id           TEXT PRIMARY KEY,
            ssh_key_id   TEXT NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
            app_id       TEXT REFERENCES apps(id) ON DELETE SET NULL,
            host_pattern TEXT,
            created_at   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS integrity (
            id           TEXT PRIMARY KEY,
            component    TEXT NOT NULL,
            path         TEXT NOT NULL,
            sha256       TEXT NOT NULL,
            version      TEXT NOT NULL,
            recorded_at  INTEGER NOT NULL,
            verified_at  INTEGER
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id           TEXT PRIMARY KEY,
            event_type   TEXT NOT NULL,
            cert_id      TEXT,
            ssh_key_id   TEXT,
            app_id       TEXT,
            detail       TEXT,
            occurred_at  INTEGER NOT NULL
        );
    ")?;

    Ok(())
}
