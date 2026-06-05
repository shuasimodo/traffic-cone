//! Binary integrity verification — AIDE-style.
//!
//! Records SHA-256 hashes of Traffic Cone binaries at install time
//! and verifies them at startup. Records are stored inside the
//! encrypted database, making them tamper-resistant without the
//! master passphrase.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::{error::StoreError, models::IntegrityRecord, store::Store};

/// The components Traffic Cone verifies.
pub const COMPONENTS: &[&str] = &["coned", "libcone.so", "cone"];

/// Record binary hashes at install time.
/// Called by the RPM post-install scriptlet via `cone verify --record`.
pub fn record(store: &Store, component: &str, path: &str, version: &str) -> Result<(), StoreError> {
    let conn = store.conn()?;
    let sha256 = crate::crypto::hash_file(path)?;
    let now = unix_now();
    let id = new_id();

    conn.execute(
        "INSERT OR REPLACE INTO integrity (id, component, path, sha256, version, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, component, path, sha256, version, now],
    )?;

    Ok(())
}

/// Verify all recorded components.
///
/// Returns Ok(()) if all pass. Returns an error describing the first
/// failure — the caller should treat any failure as a hard stop.
pub fn verify_all(store: &Store) -> Result<(), StoreError> {
    let records = list(store)?;

    for record in &records {
        verify_record(record)?;
    }

    // Update verified_at timestamps for all passing records
    let now = unix_now();
    let conn = store.conn()?;
    conn.execute("UPDATE integrity SET verified_at = ?1", rusqlite::params![now])?;

    Ok(())
}

/// Verify a single integrity record against the actual binary on disk.
pub fn verify_record(record: &IntegrityRecord) -> Result<(), StoreError> {
    let actual = crate::crypto::hash_file(&record.path)?;

    if actual != record.sha256 {
        return Err(StoreError::IntegrityFailure(format!(
            "{} at {} has been modified (expected {}, found {})",
            record.component, record.path, record.sha256, actual
        )));
    }

    Ok(())
}

/// List all integrity records.
pub fn list(store: &Store) -> Result<Vec<IntegrityRecord>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, component, path, sha256, version, recorded_at, verified_at
         FROM integrity ORDER BY component"
    )?;

    let records = stmt.query_map([], |row| {
        Ok(IntegrityRecord {
            id:          row.get(0)?,
            component:   row.get(1)?,
            path:        row.get(2)?,
            sha256:      row.get(3)?,
            version:     row.get(4)?,
            recorded_at: row.get(5)?,
            verified_at: row.get(6)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(records)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn new_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
