//! The Store — top-level handle to the Traffic Cone database.
//!
//! A Store is either locked (no passphrase in memory, database
//! inaccessible) or unlocked (passphrase-derived key held in memory,
//! all operations available).

use rusqlite::Connection;
use zeroize::Zeroizing;
use crate::{db, error::StoreError};

/// The central store handle.
///
/// Create with [`Store::open`], unlock with [`Store::unlock`].
/// All credential operations require an unlocked store.
pub struct Store {
    path: String,
    state: StoreState,
}

enum StoreState {
    Locked,
    Unlocked {
        conn: Connection,
        /// Master passphrase held in memory for per-key derivation.
        /// Zeroed on lock or drop.
        passphrase: Zeroizing<Vec<u8>>,
    },
}

impl Store {
    /// Open the store at the given path without unlocking it.
    /// Creates a new database file if one does not exist.
    pub fn open(path: impl Into<String>) -> Self {
        Store {
            path: path.into(),
            state: StoreState::Locked,
        }
    }

    /// Unlock the store with the master passphrase.
    ///
    /// Derives the SQLCipher key from the passphrase and opens
    /// the database. Returns an error if the passphrase is wrong.
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<(), StoreError> {
        // Derive the SQLCipher key from the passphrase
        let salt = self.load_or_create_db_salt(passphrase)?;
        let key = crate::crypto::derive_key(passphrase, &salt)?;
        let key_hex = hex::encode(key.as_ref());

        let conn = db::open(&self.path, &key_hex)?;

        self.state = StoreState::Unlocked {
            conn,
            passphrase: Zeroizing::new(passphrase.to_vec()),
        };

        Ok(())
    }

    /// Lock the store, zeroing the passphrase from memory.
    pub fn lock(&mut self) {
        self.state = StoreState::Locked;
    }

    /// Returns true if the store is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, StoreState::Unlocked { .. })
    }

    /// Get a reference to the database connection.
    /// Returns an error if the store is locked.
    pub(crate) fn conn(&self) -> Result<&Connection, StoreError> {
        match &self.state {
            StoreState::Unlocked { conn, .. } => Ok(conn),
            StoreState::Locked => Err(StoreError::Locked),
        }
    }

    /// Get a reference to the master passphrase.
    /// Used for per-key encryption/decryption operations.
    pub(crate) fn passphrase(&self) -> Result<&[u8], StoreError> {
        match &self.state {
            StoreState::Unlocked { passphrase, .. } => Ok(passphrase.as_ref()),
            StoreState::Locked => Err(StoreError::Locked),
        }
    }

    /// Load the database salt from a companion file, or create one on
    /// first run. The salt file lives alongside the database.
    fn load_or_create_db_salt(&self, _passphrase: &[u8]) -> Result<Vec<u8>, StoreError> {
        let salt_path = format!("{}.salt", self.path);

        if std::path::Path::new(&salt_path).exists() {
            Ok(std::fs::read(&salt_path)?)
        } else {
            let salt = crate::crypto::random_salt();
            std::fs::write(&salt_path, &salt)?;
            Ok(salt.to_vec())
        }
    }
    /// Execute a raw SQL statement — available to cone-cli for operations
    /// not yet wrapped in dedicated functions.
    pub fn execute(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<usize, StoreError> {
        Ok(self.conn()?.execute(sql, params)?)
    }
    
}

impl Drop for Store {
    fn drop(&mut self) {
        // Ensure passphrase is zeroed when the Store is dropped
        self.lock();
    }
}

