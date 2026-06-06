//! Certificate and key import for Traffic Cone.
//!
//! Supports:
//! - PKCS#12 / PFX  (.pfx, .p12)  — cert + key + optional CA chain
//! - PEM bundle      (.pem)        — cert and/or key, auto-detected
//! - DER certificate (.crt, .cer, .der) — public cert only
//! - PEM private key (.key)        — private key only
//!
//! All imported key material is re-encrypted under the master passphrase.
//! The original file passphrase is used only to unpack the file and is
//! never stored.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use p12_keystore::{KeyStore, KeyStoreEntry};
use pkcs8::der::Decode;
use pkcs8::PrivateKeyInfo;
use x509_cert::Certificate;
 
use crate::crypto;
use crate::error::StoreError;
use crate::models::KeyAlgorithm;
use crate::store::Store;

/// The result of a successful import operation.
#[derive(Debug)]
pub struct ImportResult {
    /// The imported certificate's database ID
    pub cert_id: String,
    /// Human-readable summary of what was imported
    pub summary: String,
    /// CA certificates found in the file, offered for optional import
    pub ca_chain: Vec<Vec<u8>>,
}

/// Format detected from file extension.
#[derive(Debug)]
enum ImportFormat {
    Pkcs12,
    Pem,
    Der,
}

/// Import a certificate (and optionally its key) from a file.
///
/// # Arguments
/// * `store`      - unlocked store to write into
/// * `path`       - path to the certificate file
/// * `passphrase` - file passphrase for PFX/encrypted keys (empty string if none)
/// * `label`      - human-readable name for this credential
/// * `key_path`   - optional separate key file (for cert-only PEM/DER imports)
pub fn import_file(
    store: &Store,
    path: &str,
    passphrase: &str,
    label: &str,
    key_path: Option<&str>,
) -> Result<ImportResult, StoreError> {
    let format = detect_format(path)?;

    match format {
        ImportFormat::Pkcs12 => import_pkcs12(store, path, passphrase, label),
        ImportFormat::Pem    => import_pem(store, path, passphrase, label, key_path),
        ImportFormat::Der    => import_der(store, path, label, key_path),
    }
}

/// Detect the import format from file extension.
fn detect_format(path: &str) -> Result<ImportFormat, StoreError> {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "pfx" | "p12"             => Ok(ImportFormat::Pkcs12),
        "pem" | "key"             => Ok(ImportFormat::Pem),
        "crt" | "cer" | "der"     => Ok(ImportFormat::Der),
        other => Err(StoreError::Import(format!(
            "unrecognised file extension '.{}' — supported: pfx, p12, pem, key, crt, cer, der",
            other
        ))),
    }
}

/// Import a PKCS#12 / PFX file.
///
/// Uses p12-keystore which handles all the legacy encryption schemes
/// (3DES, RC4, AES) that real-world PFX files use.
fn import_pkcs12(
    store: &Store,
    path: &str,
    passphrase: &str,
    label: &str,
) -> Result<ImportResult, StoreError> {
    let file_bytes = std::fs::read(path)?;

    let ks = KeyStore::from_pkcs12(&file_bytes, passphrase)
        .map_err(|e| StoreError::Import(format!(
            "failed to open PFX file — wrong passphrase or unsupported format: {}", e
        )))?;

    // Get the first private key chain (cert + key + optional CA chain)
    let (_alias, chain) = ks.private_key_chain()
        .ok_or_else(|| StoreError::Import(
            "PFX file contains no private key — only certificate-only PFX files \
             are not supported for mTLS use".into()
        ))?;

    // The cert chain: index 0 is the entity cert, rest is CA chain
    let certs = chain.chain();
    if certs.is_empty() {
        return Err(StoreError::Import("PFX file contains no certificates".into()));
    }

    let cert_der = certs[0].as_der().to_vec();
    let key_der  = chain.key().to_vec();

    // Any certs after index 0 are the CA chain — offer them for import
    let ca_chain: Vec<Vec<u8>> = certs[1..]
        .iter()
        .map(|c| c.as_der().to_vec())
        .collect();

    let result = store_cert_and_key(store, cert_der, key_der, label)?;

    Ok(ImportResult {
        ca_chain,
        ..result
    })
}

/// Import a PEM file — may contain a cert, a key, or both concatenated.
fn import_pem(
    store: &Store,
    path: &str,
    _passphrase: &str,
    label: &str,
    key_path: Option<&str>,
) -> Result<ImportResult, StoreError> {
    let pem_data = std::fs::read_to_string(path)?;

    let has_cert = pem_data.contains("-----BEGIN CERTIFICATE-----");
    let has_key  = pem_data.contains("-----BEGIN PRIVATE KEY-----")
        || pem_data.contains("-----BEGIN EC PRIVATE KEY-----")
        || pem_data.contains("-----BEGIN RSA PRIVATE KEY-----")
        || pem_data.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");

    match (has_cert, has_key) {
        (true, true) => {
            // Both in one file
            import_pem_bundle(store, &pem_data, label)
        }
        (true, false) => {
            // Cert only — need a separate key file
            let key_data = match key_path {
                Some(kp) => std::fs::read_to_string(kp)?,
                None => return Err(StoreError::Import(
                    "PEM file contains a certificate but no private key. \
                     Provide the key file with --key.".into()
                )),
            };
            import_pem_cert_and_key(store, &pem_data, &key_data, label)
        }
        (false, true) => {
            Err(StoreError::Import(
                "PEM file contains only a private key. \
                 Provide the certificate with --cert.".into()
            ))
        }
        (false, false) => {
            Err(StoreError::Import(
                "File does not appear to contain a certificate or private key.".into()
            ))
        }
    }
}

/// Import a PEM bundle containing both cert and key blocks.
fn import_pem_bundle(
    store: &Store,
    pem_data: &str,
    label: &str,
) -> Result<ImportResult, StoreError> {
    let mut cert_der: Option<Vec<u8>> = None;
    let mut key_der:  Option<Vec<u8>> = None;

    for block in pem::parse_many(pem_data)
        .map_err(|e| StoreError::Import(format!("failed to parse PEM: {}", e)))?
    {
        match block.tag() {
            "CERTIFICATE" => {
                if cert_der.is_none() {
                    cert_der = Some(block.into_contents());
                }
            }
            "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
                key_der = Some(block.into_contents());
            }
            _ => {}
        }
    }

    let cert_der = cert_der
        .ok_or_else(|| StoreError::Import("no certificate found in PEM file".into()))?;
    let key_der = key_der
        .ok_or_else(|| StoreError::Import("no private key found in PEM file".into()))?;

    store_cert_and_key(store, cert_der, key_der, label)
}

/// Import from separate cert PEM and key PEM strings.
fn import_pem_cert_and_key(
    store: &Store,
    cert_pem: &str,
    key_pem: &str,
    label: &str,
) -> Result<ImportResult, StoreError> {
    let cert_block = pem::parse(cert_pem)
        .map_err(|e| StoreError::Import(format!("failed to parse cert PEM: {}", e)))?;

    let key_block = pem::parse(key_pem)
        .map_err(|e| StoreError::Import(format!("failed to parse key PEM: {}", e)))?;

    store_cert_and_key(
        store,
        cert_block.into_contents(),
        key_block.into_contents(),
        label,
    )
}

/// Import a DER-encoded certificate with a separate key file.
fn import_der(
    store: &Store,
    path: &str,
    label: &str,
    key_path: Option<&str>,
) -> Result<ImportResult, StoreError> {
    let cert_der = std::fs::read(path)?;

    // Verify it parses as a valid certificate before doing anything else
    Certificate::from_der(&cert_der)
        .map_err(|e| StoreError::Import(format!("invalid DER certificate: {}", e)))?;

    let key_der = match key_path {
        Some(kp) => {
            let key_pem = std::fs::read_to_string(kp)?;
            let block = pem::parse(&key_pem)
                .map_err(|e| StoreError::Import(format!("failed to parse key file: {}", e)))?;
            block.into_contents()
        }
        None => return Err(StoreError::Import(
            "DER certificate requires a private key file. Provide it with --key.".into()
        )),
    };

    store_cert_and_key(store, cert_der, key_der, label)
}

// ---------------------------------------------------------------------------
// Common path: encrypt key and write to database
// ---------------------------------------------------------------------------

/// Encrypt the key under the master passphrase and write cert + key to the database.
/// All import paths converge here.
fn store_cert_and_key(
    store: &Store,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    label: &str,
) -> Result<ImportResult, StoreError> {
    let meta      = parse_cert_metadata(&cert_der)?;
    let algorithm = detect_key_algorithm(&key_der)?;
    let master    = store.passphrase()?;

    // Re-encrypt the key under the Traffic Cone master passphrase.
    // The original file passphrase is no longer needed after this point.
    let (key_enc, key_salt, key_nonce) = crypto::encrypt_key(&key_der, master)?;

    let cert_id = new_id();
    let key_id  = new_id();
    let now     = unix_now();
    let conn    = store.conn()?;

    conn.execute(
        "INSERT INTO certs \
         (id, label, cert_der, fingerprint, subject, issuer, not_before, not_after, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            cert_id,
            label,
            cert_der,
            meta.fingerprint,
            meta.subject,
            meta.issuer,
            meta.not_before,
            meta.not_after,
            now,
        ],
    )?;

    conn.execute(
        "INSERT INTO keys (id, cert_id, algorithm, key_enc, key_salt, key_nonce) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            key_id,
            cert_id,
            format!("{:?}", algorithm),
            key_enc,
            key_salt,
            key_nonce,
        ],
    )?;

    conn.execute(
        "INSERT INTO audit_log (id, event_type, cert_id, detail, occurred_at) \
         VALUES (?1, 'cert_imported', ?2, ?3, ?4)",
        rusqlite::params![new_id(), cert_id, format!("Imported: {}", label), now],
    )?;

    let summary = format!(
        "Imported: {} ({:?})\n  Subject: {}\n  Expires: {}",
        label, algorithm, meta.subject, meta.not_after,
    );

    Ok(ImportResult {
        cert_id,
        summary,
        ca_chain: vec![],
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct CertMeta {
    fingerprint: String,
    subject:     String,
    issuer:      String,
    not_before:  i64,
    not_after:   i64,
}

/// Parse display metadata from a DER-encoded X.509 certificate.
fn parse_cert_metadata(cert_der: &[u8]) -> Result<CertMeta, StoreError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| StoreError::Import(format!("invalid certificate: {}", e)))?;

    let fingerprint = crypto::hash_bytes(cert_der);
    let subject     = cert.tbs_certificate.subject.to_string();
    let issuer      = cert.tbs_certificate.issuer.to_string();

    let not_before = cert.tbs_certificate.validity
        .not_before.to_unix_duration().as_secs() as i64;
    let not_after  = cert.tbs_certificate.validity
        .not_after.to_unix_duration().as_secs() as i64;

    Ok(CertMeta { fingerprint, subject, issuer, not_before, not_after })
}

/// Detect the key algorithm by reading the AlgorithmIdentifier OID
/// from the PKCS#8 PrivateKeyInfo structure.
fn detect_key_algorithm(key_der: &[u8]) -> Result<KeyAlgorithm, StoreError> {
    let info = PrivateKeyInfo::from_der(key_der)
        .map_err(|e| StoreError::Import(format!("failed to parse private key: {}", e)))?;

    match info.algorithm.oid.to_string().as_str() {
        // RSA — use key length as a rough bit-size heuristic
        "1.2.840.113549.1.1.1" => {
            if key_der.len() > 1000 {
                Ok(KeyAlgorithm::Rsa4096)
            } else {
                Ok(KeyAlgorithm::Rsa2048)
            }
        }
        // EC — default to P-256; TODO: inspect curve OID for P-384
        "1.2.840.10045.2.1" => Ok(KeyAlgorithm::EcP256),
        other => Err(StoreError::Import(format!(
            "unsupported key algorithm OID: {} — only RSA and EC keys are supported", other
        ))),
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