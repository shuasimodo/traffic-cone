//! Certificate export and encrypted backup for Traffic Cone.
//!
//! Two operations:
//!
//! 1. **Single cert export** — re-exports a stored cert + key as a PFX file,
//!    encrypted with a user-supplied export passphrase. Useful for transferring
//!    a cert to another device or application.
//!
//! 2. **Full backup** — exports the entire store (all certs, keys, SSH keys,
//!    CA certs, routes, apps) as an encrypted `.cone` file using age encryption.
//!    The backup passphrase is independent from the master passphrase.
//!    Restoring requires both passphrases.

use std::time::{SystemTime, UNIX_EPOCH};
use p12_keystore::{Certificate, EncryptionAlgorithm, KeyStore, MacAlgorithm, PrivateKeyChain};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::StoreError;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Single cert export
// ---------------------------------------------------------------------------

/// Export a single certificate and its private key as a PFX file.
///
/// The key is decrypted from the store using the master passphrase,
/// then re-encrypted into a PFX using the provided export passphrase.
/// The export passphrase does not need to match the master passphrase.
///
/// # Arguments
/// * `store`           - unlocked store
/// * `cert_id`         - ID of the cert to export
/// * `export_password` - passphrase for the output PFX file
pub fn export_pfx(
    store: &Store,
    cert_id: &str,
    export_password: &str,
) -> Result<Vec<u8>, StoreError> {
    let conn = store.conn()?;

    // Load the certificate DER bytes
    let cert_der: Vec<u8> = conn.query_row(
        "SELECT cert_der FROM certs WHERE id = ?1",
        rusqlite::params![cert_id],
        |row| row.get(0),
    ).map_err(|_| StoreError::NotFound(format!("certificate {} not found", cert_id)))?;

    // Load the encrypted key
    let (key_enc, key_salt, key_nonce): (Vec<u8>, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT key_enc, key_salt, key_nonce FROM keys WHERE cert_id = ?1",
        rusqlite::params![cert_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|_| StoreError::NotFound(format!("private key for cert {} not found", cert_id)))?;

    // Decrypt the key using the master passphrase
    let master = store.passphrase()?;
    let key_plaintext: Zeroizing<Vec<u8>> =
        crypto::decrypt_key(&key_enc, &key_salt, &key_nonce, master)?;

    // Build a p12-keystore KeyStore and write it as PFX
    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| StoreError::Crypto(format!("failed to parse stored certificate: {}", e)))?;

    let chain = PrivateKeyChain::new(
        key_plaintext.as_slice(),
        b"traffic-cone",
        vec![cert],
    );

    let mut ks = KeyStore::new();
    ks.add_entry("certificate", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));

    let pfx_bytes = ks
        .writer(export_password)
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .write()
        .map_err(|e| StoreError::Crypto(format!("failed to write PFX: {}", e)))?;

    // Audit log
    let now = unix_now();
    conn.execute(
        "INSERT INTO audit_log (id, event_type, cert_id, detail, occurred_at) \
         VALUES (?1, 'cert_exported', ?2, 'Exported as PFX', ?3)",
        rusqlite::params![new_id(), cert_id, now],
    )?;

    Ok(pfx_bytes)
}

// ---------------------------------------------------------------------------
// Full backup
// ---------------------------------------------------------------------------

/// Contents of a Traffic Cone backup.
/// Serialised to JSON, then encrypted with age.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupPayload {
    pub version:  u32,
    pub exported_at: i64,
    pub certs:    Vec<BackupCert>,
    pub ssh_keys: Vec<BackupSshKey>,
    pub ca_certs: Vec<BackupCaCert>,
    pub apps:     Vec<BackupApp>,
    pub routes:   Vec<BackupRoute>,
    pub ssh_routes: Vec<BackupSshRoute>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupCert {
    pub id:          String,
    pub label:       String,
    pub cert_der:    String,   // hex-encoded
    pub fingerprint: String,
    pub subject:     String,
    pub issuer:      String,
    pub not_before:  i64,
    pub not_after:   i64,
    pub created_at:  i64,
    // Key material — still encrypted under master passphrase.
    // Restoring requires both backup passphrase AND master passphrase.
    pub key_enc:     String,   // hex-encoded
    pub key_salt:    String,   // hex-encoded
    pub key_nonce:   String,   // hex-encoded
    pub key_algorithm: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupSshKey {
    pub id:         String,
    pub label:      String,
    pub public_key: String,
    pub algorithm:  String,
    pub key_enc:    String,
    pub key_salt:   String,
    pub key_nonce:  String,
    pub created_at: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupCaCert {
    pub id:          String,
    pub label:       String,
    pub cert_pem:    String,
    pub fingerprint: String,
    pub subject:     String,
    pub not_after:   i64,
    pub created_at:  i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupApp {
    pub id:            String,
    pub label:         String,
    pub exe_path:      String,
    pub exe_hash:      String,
    pub registered_at: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupRoute {
    pub id:           String,
    pub cert_id:      String,
    pub app_id:       Option<String>,
    pub match_type:   String,
    pub pattern:      Option<String>,
    pub require_both: bool,
    pub priority:     i64,
    pub created_at:   i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BackupSshRoute {
    pub id:           String,
    pub ssh_key_id:   String,
    pub app_id:       Option<String>,
    pub host_pattern: Option<String>,
    pub created_at:   i64,
}

/// Create a full encrypted backup of the store.
///
/// The backup is structured as:
/// ```text
/// age-encrypt(backup_passphrase, JSON(BackupPayload))
/// ```
///
/// Key material in the payload is still encrypted under the master passphrase.
/// Both passphrases are required to actually use the extracted key material.
///
/// # Arguments
/// * `store`           - unlocked store
/// * `backup_password` - passphrase for the backup file (independent of master)
pub fn create_backup(
    store: &Store,
    backup_password: &str,
) -> Result<Vec<u8>, StoreError> {
    let payload = collect_backup_payload(store)?;

    let json = serde_json::to_vec_pretty(&payload)
        .map_err(|e| StoreError::Crypto(format!("failed to serialise backup: {}", e)))?;

    // Encrypt with age (passphrase mode)
    let encrypted = age_encrypt(&json, backup_password)?;

    // Audit log
    let conn = store.conn()?;
    conn.execute(
        "INSERT INTO audit_log (id, event_type, detail, occurred_at) \
         VALUES (?1, 'backup_created', 'Full backup created', ?2)",
        rusqlite::params![new_id(), unix_now()],
    )?;

    Ok(encrypted)
}

/// Restore a backup created by [`create_backup`].
///
/// Decrypts the backup file, parses the payload, and writes all entries
/// into the store. Existing entries with matching fingerprints are skipped.
///
/// # Arguments
/// * `store`           - unlocked store to restore into
/// * `backup_data`     - raw bytes of the `.cone` backup file
/// * `backup_password` - passphrase used when the backup was created
pub fn restore_backup(
    store: &Store,
    backup_data: &[u8],
    backup_password: &str,
) -> Result<RestoreResult, StoreError> {
    let json = age_decrypt(backup_data, backup_password)?;

    let payload: BackupPayload = serde_json::from_slice(&json)
        .map_err(|e| StoreError::Import(format!("failed to parse backup: {}", e)))?;

    let mut result = RestoreResult::default();
    let conn = store.conn()?;
    let now = unix_now();

    // Restore CA certs
    for ca in &payload.ca_certs {
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM ca_certs WHERE fingerprint = ?1",
            rusqlite::params![ca.fingerprint],
            |row| row.get::<_, i64>(0),
        ).map(|n| n > 0).unwrap_or(false);

        if !exists {
            conn.execute(
                "INSERT INTO ca_certs \
                 (id, label, cert_pem, fingerprint, subject, not_after, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    ca.id, ca.label, ca.cert_pem, ca.fingerprint,
                    ca.subject, ca.not_after, ca.created_at,
                ],
            )?;
            result.ca_certs += 1;
        }
    }

    // Restore TLS certs + keys
    for c in &payload.certs {
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM certs WHERE fingerprint = ?1",
            rusqlite::params![c.fingerprint],
            |row| row.get::<_, i64>(0),
        ).map(|n| n > 0).unwrap_or(false);

        if !exists {
            let cert_der = hex::decode(&c.cert_der)
                .map_err(|e| StoreError::Import(format!("invalid cert data in backup: {}", e)))?;

            conn.execute(
                "INSERT INTO certs \
                 (id, label, cert_der, fingerprint, subject, issuer, \
                  not_before, not_after, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    c.id, c.label, cert_der, c.fingerprint,
                    c.subject, c.issuer, c.not_before, c.not_after, c.created_at,
                ],
            )?;

            conn.execute(
                "INSERT INTO keys \
                 (id, cert_id, algorithm, key_enc, key_salt, key_nonce) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    new_id(), c.id, c.key_algorithm,
                    hex::decode(&c.key_enc).unwrap_or_default(),
                    hex::decode(&c.key_salt).unwrap_or_default(),
                    hex::decode(&c.key_nonce).unwrap_or_default(),
                ],
            )?;

            result.certs += 1;
        }
    }

    // Restore SSH keys
    for k in &payload.ssh_keys {
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM ssh_keys WHERE id = ?1",
            rusqlite::params![k.id],
            |row| row.get::<_, i64>(0),
        ).map(|n| n > 0).unwrap_or(false);

        if !exists {
            conn.execute(
                "INSERT INTO ssh_keys \
                 (id, label, public_key, algorithm, key_enc, key_salt, key_nonce, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    k.id, k.label, k.public_key, k.algorithm,
                    hex::decode(&k.key_enc).unwrap_or_default(),
                    hex::decode(&k.key_salt).unwrap_or_default(),
                    hex::decode(&k.key_nonce).unwrap_or_default(),
                    k.created_at,
                ],
            )?;
            result.ssh_keys += 1;
        }
    }

    // Restore apps
    for app in &payload.apps {
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM apps WHERE exe_path = ?1",
            rusqlite::params![app.exe_path],
            |row| row.get::<_, i64>(0),
        ).map(|n| n > 0).unwrap_or(false);

        if !exists {
            conn.execute(
                "INSERT INTO apps (id, label, exe_path, exe_hash, registered_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    app.id, app.label, app.exe_path,
                    app.exe_hash, app.registered_at,
                ],
            )?;
            result.apps += 1;
        }
    }

    // Restore routes
    for r in &payload.routes {
        conn.execute(
            "INSERT OR IGNORE INTO routes \
             (id, cert_id, app_id, match_type, pattern, require_both, priority, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                r.id, r.cert_id, r.app_id, r.match_type,
                r.pattern, r.require_both as i64, r.priority, r.created_at,
            ],
        )?;
        result.routes += 1;
    }

    // Restore SSH routes
    for r in &payload.ssh_routes {
        conn.execute(
            "INSERT OR IGNORE INTO ssh_routes \
             (id, ssh_key_id, app_id, host_pattern, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![r.id, r.ssh_key_id, r.app_id, r.host_pattern, r.created_at],
        )?;
        result.ssh_routes += 1;
    }

    // Audit log
    conn.execute(
        "INSERT INTO audit_log (id, event_type, detail, occurred_at) \
         VALUES (?1, 'backup_restored', ?2, ?3)",
        rusqlite::params![
            new_id(),
            format!("Restored: {} certs, {} SSH keys, {} apps",
                result.certs, result.ssh_keys, result.apps),
            now,
        ],
    )?;

    Ok(result)
}

/// Summary of what was restored.
#[derive(Debug, Default)]
pub struct RestoreResult {
    pub certs:      usize,
    pub ssh_keys:   usize,
    pub ca_certs:   usize,
    pub apps:       usize,
    pub routes:     usize,
    pub ssh_routes: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect all data from the store into a BackupPayload.
fn collect_backup_payload(store: &Store) -> Result<BackupPayload, StoreError> {
    let conn = store.conn()?;

    // Certs + keys
    let mut stmt = conn.prepare(
        "SELECT c.id, c.label, c.cert_der, c.fingerprint, c.subject, c.issuer,
                c.not_before, c.not_after, c.created_at,
                k.key_enc, k.key_salt, k.key_nonce, k.algorithm
         FROM certs c
         JOIN keys k ON k.cert_id = c.id"
    )?;

    let certs = stmt.query_map([], |row| {
        Ok(BackupCert {
            id:            row.get(0)?,
            label:         row.get(1)?,
            cert_der:      hex::encode(row.get::<_, Vec<u8>>(2)?),
            fingerprint:   row.get(3)?,
            subject:       row.get(4)?,
            issuer:        row.get(5)?,
            not_before:    row.get(6)?,
            not_after:     row.get(7)?,
            created_at:    row.get(8)?,
            key_enc:       hex::encode(row.get::<_, Vec<u8>>(9)?),
            key_salt:      hex::encode(row.get::<_, Vec<u8>>(10)?),
            key_nonce:     hex::encode(row.get::<_, Vec<u8>>(11)?),
            key_algorithm: row.get(12)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    // SSH keys
    let mut stmt = conn.prepare(
        "SELECT id, label, public_key, algorithm, key_enc, key_salt, key_nonce, created_at
         FROM ssh_keys"
    )?;

    let ssh_keys = stmt.query_map([], |row| {
        Ok(BackupSshKey {
            id:         row.get(0)?,
            label:      row.get(1)?,
            public_key: row.get(2)?,
            algorithm:  row.get(3)?,
            key_enc:    hex::encode(row.get::<_, Vec<u8>>(4)?),
            key_salt:   hex::encode(row.get::<_, Vec<u8>>(5)?),
            key_nonce:  hex::encode(row.get::<_, Vec<u8>>(6)?),
            created_at: row.get(7)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    // CA certs
    let mut stmt = conn.prepare(
        "SELECT id, label, cert_pem, fingerprint, subject, not_after, created_at
         FROM ca_certs"
    )?;

    let ca_certs = stmt.query_map([], |row| {
        Ok(BackupCaCert {
            id:          row.get(0)?,
            label:       row.get(1)?,
            cert_pem:    row.get(2)?,
            fingerprint: row.get(3)?,
            subject:     row.get(4)?,
            not_after:   row.get(5)?,
            created_at:  row.get(6)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    // Apps
    let mut stmt = conn.prepare(
        "SELECT id, label, exe_path, exe_hash, registered_at FROM apps"
    )?;

    let apps = stmt.query_map([], |row| {
        Ok(BackupApp {
            id:            row.get(0)?,
            label:         row.get(1)?,
            exe_path:      row.get(2)?,
            exe_hash:      row.get(3)?,
            registered_at: row.get(4)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    // Routes
    let mut stmt = conn.prepare(
        "SELECT id, cert_id, app_id, match_type, pattern, require_both, priority, created_at
         FROM routes"
    )?;

    let routes = stmt.query_map([], |row| {
        Ok(BackupRoute {
            id:           row.get(0)?,
            cert_id:      row.get(1)?,
            app_id:       row.get(2)?,
            match_type:   row.get(3)?,
            pattern:      row.get(4)?,
            require_both: row.get::<_, i64>(5)? != 0,
            priority:     row.get(6)?,
            created_at:   row.get(7)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    // SSH routes
    let mut stmt = conn.prepare(
        "SELECT id, ssh_key_id, app_id, host_pattern, created_at FROM ssh_routes"
    )?;

    let ssh_routes = stmt.query_map([], |row| {
        Ok(BackupSshRoute {
            id:           row.get(0)?,
            ssh_key_id:   row.get(1)?,
            app_id:       row.get(2)?,
            host_pattern: row.get(3)?,
            created_at:   row.get(4)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;

    Ok(BackupPayload {
        version: 1,
        exported_at: unix_now(),
        certs,
        ssh_keys,
        ca_certs,
        apps,
        routes,
        ssh_routes,
    })
}

/// Encrypt bytes using age passphrase mode.
fn age_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, StoreError> {
    use age::secrecy::SecretString;

    let passphrase = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut output = vec![];
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| StoreError::Crypto(format!("age encrypt error: {}", e)))?;

    std::io::Write::write_all(&mut writer, plaintext)
        .map_err(|e| StoreError::Crypto(format!("age write error: {}", e)))?;

    writer.finish()
        .map_err(|e| StoreError::Crypto(format!("age finish error: {}", e)))?;

    Ok(output)
}

/// Decrypt bytes using age passphrase mode.
fn age_decrypt(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, StoreError> {
    use age::secrecy::SecretString;
    use std::io::Read;

    let passphrase = SecretString::from(passphrase.to_string());

    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| StoreError::Crypto(format!("age decrypt init error: {}", e)))?;

    let mut reader = match decryptor {
        age::Decryptor::Passphrase(d) => d
            .decrypt(&passphrase, None)
            .map_err(|e| StoreError::Crypto(format!(
                "backup decryption failed — wrong passphrase?: {}", e
            )))?,
        _ => return Err(StoreError::Crypto(
            "backup was not encrypted with a passphrase".into()
        )),
    };

    let mut output = vec![];
    reader.read_to_end(&mut output)
        .map_err(|e| StoreError::Crypto(format!("age read error: {}", e)))?;

    Ok(output)
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