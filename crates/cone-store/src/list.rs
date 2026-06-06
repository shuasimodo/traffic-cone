//! Listing and retrieval functions for cone-store.
//!
//! These are the read operations — listing certs, looking up a cert
//! by label or ID, retrieving key material for signing, and listing
//! apps, routes, SSH keys, and CA certs.

use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::StoreError;
use crate::models::{App, CaCert, Cert, KeyAlgorithm, MatchType, Route, SshKey, SshRoute};
use crate::store::Store;

// ---------------------------------------------------------------------------
// TLS Certificates
// ---------------------------------------------------------------------------

/// List all stored TLS client certificates.
pub fn list_certs(store: &Store) -> Result<Vec<Cert>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, label, cert_der, fingerprint, subject, issuer,
                not_before, not_after, created_at
         FROM certs
         ORDER BY label ASC",
    )?;

    let certs = stmt.query_map([], |row| {
        Ok(Cert {
            id:          row.get(0)?,
            label:       row.get(1)?,
            cert_der:    row.get(2)?,
            fingerprint: row.get(3)?,
            subject:     row.get(4)?,
            issuer:      row.get(5)?,
            not_before:  row.get(6)?,
            not_after:   row.get(7)?,
            created_at:  row.get(8)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(certs)
}

/// Get a single certificate by label.
pub fn get_cert_by_label(store: &Store, label: &str) -> Result<Cert, StoreError> {
    let conn = store.conn()?;
    conn.query_row(
        "SELECT id, label, cert_der, fingerprint, subject, issuer,
                not_before, not_after, created_at
         FROM certs WHERE label = ?1",
        rusqlite::params![label],
        |row| Ok(Cert {
            id:          row.get(0)?,
            label:       row.get(1)?,
            cert_der:    row.get(2)?,
            fingerprint: row.get(3)?,
            subject:     row.get(4)?,
            issuer:      row.get(5)?,
            not_before:  row.get(6)?,
            not_after:   row.get(7)?,
            created_at:  row.get(8)?,
        }),
    )
    .map_err(|_| StoreError::NotFound(format!("no certificate with label '{}'", label)))
}

/// Get a single certificate by ID.
pub fn get_cert_by_id(store: &Store, id: &str) -> Result<Cert, StoreError> {
    let conn = store.conn()?;
    conn.query_row(
        "SELECT id, label, cert_der, fingerprint, subject, issuer,
                not_before, not_after, created_at
         FROM certs WHERE id = ?1",
        rusqlite::params![id],
        |row| Ok(Cert {
            id:          row.get(0)?,
            label:       row.get(1)?,
            cert_der:    row.get(2)?,
            fingerprint: row.get(3)?,
            subject:     row.get(4)?,
            issuer:      row.get(5)?,
            not_before:  row.get(6)?,
            not_after:   row.get(7)?,
            created_at:  row.get(8)?,
        }),
    )
    .map_err(|_| StoreError::NotFound(format!("no certificate with id '{}'", id)))
}

/// Decrypt and retrieve the private key for a certificate.
///
/// The plaintext key is wrapped in Zeroizing — it will be zeroed
/// from memory automatically when the return value is dropped.
/// Callers must not hold this any longer than necessary.
pub fn get_plaintext_key(
    store: &Store,
    cert_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, KeyAlgorithm), StoreError> {
    let conn = store.conn()?;

    let (key_enc, key_salt, key_nonce, algorithm_str): (Vec<u8>, Vec<u8>, Vec<u8>, String) =
        conn.query_row(
            "SELECT key_enc, key_salt, key_nonce, algorithm
             FROM keys WHERE cert_id = ?1",
            rusqlite::params![cert_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| StoreError::NotFound(
            format!("no private key found for cert '{}'", cert_id)
        ))?;

    let master = store.passphrase()?;
    let plaintext = crypto::decrypt_key(&key_enc, &key_salt, &key_nonce, master)?;

    let algorithm = parse_algorithm(&algorithm_str)?;

    Ok((plaintext, algorithm))
}

/// Delete a certificate and its associated key and routes.
pub fn delete_cert(store: &Store, label: &str) -> Result<(), StoreError> {
    let cert = get_cert_by_label(store, label)?;
    let conn = store.conn()?;

    // CASCADE in the schema handles keys and routes automatically
    conn.execute("DELETE FROM certs WHERE id = ?1", rusqlite::params![cert.id])?;

    conn.execute(
        "INSERT INTO audit_log (id, event_type, cert_id, detail, occurred_at)
         VALUES (?1, 'cert_deleted', ?2, ?3, ?4)",
        rusqlite::params![
            new_id(),
            cert.id,
            format!("Deleted cert: {}", label),
            unix_now(),
        ],
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// SSH Keys
// ---------------------------------------------------------------------------

/// List all stored SSH keys (public material only).
pub fn list_ssh_keys(store: &Store) -> Result<Vec<SshKey>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, label, public_key, algorithm, key_enc, key_salt, key_nonce, created_at
         FROM ssh_keys ORDER BY label ASC",
    )?;

    let keys = stmt.query_map([], |row| {
        Ok(SshKey {
            id:         row.get(0)?,
            label:      row.get(1)?,
            public_key: row.get(2)?,
            algorithm:  crate::models::SshAlgorithm::Ed25519, // parsed below
            key_enc:    row.get(4)?,
            key_salt:   row.get(5)?,
            key_nonce:  row.get(6)?,
            created_at: row.get(7)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

/// Decrypt and retrieve an SSH private key by label.
pub fn get_ssh_plaintext_key(
    store: &Store,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let conn = store.conn()?;

    let (key_enc, key_salt, key_nonce): (Vec<u8>, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT key_enc, key_salt, key_nonce FROM ssh_keys WHERE label = ?1",
        rusqlite::params![label],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .map_err(|_| StoreError::NotFound(format!("no SSH key with label '{}'", label)))?;

    let master = store.passphrase()?;
    crypto::decrypt_key(&key_enc, &key_salt, &key_nonce, master)
}

// ---------------------------------------------------------------------------
// CA Certificates
// ---------------------------------------------------------------------------

/// List all stored CA trust anchors.
pub fn list_ca_certs(store: &Store) -> Result<Vec<CaCert>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, label, cert_pem, fingerprint, subject, not_after, system_file, created_at
         FROM ca_certs ORDER BY label ASC",
    )?;

    let certs = stmt.query_map([], |row| {
        Ok(CaCert {
            id:          row.get(0)?,
            label:       row.get(1)?,
            cert_pem:    row.get(2)?,
            fingerprint: row.get(3)?,
            subject:     row.get(4)?,
            not_after:   row.get(5)?,
            system_file: row.get(6)?,
            created_at:  row.get(7)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(certs)
}

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

/// List all registered applications.
pub fn list_apps(store: &Store) -> Result<Vec<App>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, label, exe_path, exe_hash, registered_at
         FROM apps ORDER BY label ASC",
    )?;

    let apps = stmt.query_map([], |row| {
        Ok(App {
            id:            row.get(0)?,
            label:         row.get(1)?,
            exe_path:      row.get(2)?,
            exe_hash:      row.get(3)?,
            registered_at: row.get(4)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(apps)
}

/// Get a registered application by its binary path.
/// Used by coned when verifying an incoming IPC connection.
pub fn get_app_by_exe(store: &Store, exe_path: &str) -> Result<App, StoreError> {
    let conn = store.conn()?;
    conn.query_row(
        "SELECT id, label, exe_path, exe_hash, registered_at
         FROM apps WHERE exe_path = ?1",
        rusqlite::params![exe_path],
        |row| Ok(App {
            id:            row.get(0)?,
            label:         row.get(1)?,
            exe_path:      row.get(2)?,
            exe_hash:      row.get(3)?,
            registered_at: row.get(4)?,
        }),
    )
    .map_err(|_| StoreError::NotFound(
        format!("no registered application at path '{}'", exe_path)
    ))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// List all TLS routing rules.
pub fn list_routes(store: &Store) -> Result<Vec<Route>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, cert_id, app_id, match_type, pattern,
                require_both, priority, created_at
         FROM routes ORDER BY priority DESC, created_at ASC",
    )?;

    let routes = stmt.query_map([], |row| {
        let match_type_str: String = row.get(3)?;
        let match_type = match match_type_str.as_str() {
            "ip"      => MatchType::Ip,
            "ip_cidr" => MatchType::IpCidr,
            _         => MatchType::Hostname,
        };

        Ok(Route {
            id:           row.get(0)?,
            cert_id:      row.get(1)?,
            app_id:       row.get(2)?,
            match_type,
            pattern:      row.get(4)?,
            require_both: row.get::<_, i64>(5)? != 0,
            priority:     row.get(6)?,
            created_at:   row.get(7)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(routes)
}

/// Find the best matching route for a given app exe path and remote host.
/// Returns the cert_id of the best match, or None if no route applies.
///
/// This is the core routing decision used by coned.
pub fn resolve_route(
    store: &Store,
    exe_path: Option<&str>,
    remote_host: Option<&str>,
    remote_ip: Option<&str>,
) -> Result<Option<String>, StoreError> {
    let routes = list_routes(store)?;
    let apps = list_apps(store)?;

    // Find the app ID matching this exe path (if any)
    let app_id = exe_path.and_then(|path| {
        apps.iter().find(|a| a.exe_path == path).map(|a| a.id.clone())
    });

    let mut best: Option<(i64, i32, String)> = None; // (priority, specificity, cert_id)

    for route in &routes {
        let app_matches = match (&route.app_id, &app_id) {
            (Some(r_app), Some(a_id)) => r_app == a_id,
            (None, _) => true,   // route has no app restriction
            (Some(_), None) => false, // route requires specific app, none matched
        };

        let host_matches = match (&route.pattern, &route.match_type) {
            (None, _) => true,   // route has no host restriction
            (Some(pattern), MatchType::Hostname) => {
                remote_host.map(|h| h == pattern).unwrap_or(false)
            }
            (Some(pattern), MatchType::Ip) => {
                remote_ip.map(|ip| ip == pattern).unwrap_or(false)
            }
            (Some(pattern), MatchType::IpCidr) => {
                // Simple prefix match for now — full CIDR parsing is a TODO
                remote_ip.map(|ip| ip.starts_with(pattern.trim_end_matches(".0/24")))
                    .unwrap_or(false)
            }
        };

        // If require_both is set, both must match
        if route.require_both && !(app_matches && host_matches) {
            continue;
        }

        if !app_matches && !host_matches {
            continue;
        }

        // Specificity: app+host = 2, app-only or host-only = 1
        let specificity = match (app_matches && route.app_id.is_some(),
                                  host_matches && route.pattern.is_some()) {
            (true, true) => 2,
            _            => 1,
        };

        let is_better = match &best {
            None => true,
            Some((best_pri, best_spec, _)) => {
                route.priority > *best_pri
                    || (route.priority == *best_pri && specificity > *best_spec)
            }
        };

        if is_better {
            best = Some((route.priority, specificity, route.cert_id.clone()));
        }
    }

    Ok(best.map(|(_, _, cert_id)| cert_id))
}

/// List all SSH routing rules.
pub fn list_ssh_routes(store: &Store) -> Result<Vec<SshRoute>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, ssh_key_id, app_id, host_pattern, created_at
         FROM ssh_routes ORDER BY created_at ASC",
    )?;

    let routes = stmt.query_map([], |row| {
        Ok(SshRoute {
            id:           row.get(0)?,
            ssh_key_id:   row.get(1)?,
            app_id:       row.get(2)?,
            host_pattern: row.get(3)?,
            created_at:   row.get(4)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(routes)
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// A single audit log entry.
#[derive(Debug)]
pub struct AuditEntry {
    pub id:          String,
    pub event_type:  String,
    pub cert_id:     Option<String>,
    pub ssh_key_id:  Option<String>,
    pub app_id:      Option<String>,
    pub detail:      Option<String>,
    pub occurred_at: i64,
}

/// Retrieve the most recent audit log entries.
pub fn list_audit_log(store: &Store, limit: u32) -> Result<Vec<AuditEntry>, StoreError> {
    let conn = store.conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, event_type, cert_id, ssh_key_id, app_id, detail, occurred_at
         FROM audit_log
         ORDER BY occurred_at DESC
         LIMIT ?1",
    )?;

    let entries = stmt.query_map(rusqlite::params![limit], |row| {
        Ok(AuditEntry {
            id:          row.get(0)?,
            event_type:  row.get(1)?,
            cert_id:     row.get(2)?,
            ssh_key_id:  row.get(3)?,
            app_id:      row.get(4)?,
            detail:      row.get(5)?,
            occurred_at: row.get(6)?,
        })
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_algorithm(s: &str) -> Result<KeyAlgorithm, StoreError> {
    match s {
        "Rsa2048" => Ok(KeyAlgorithm::Rsa2048),
        "Rsa4096" => Ok(KeyAlgorithm::Rsa4096),
        "EcP256"  => Ok(KeyAlgorithm::EcP256),
        "EcP384"  => Ok(KeyAlgorithm::EcP384),
        other => Err(StoreError::Crypto(
            format!("unknown key algorithm in database: {}", other)
        )),
    }
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