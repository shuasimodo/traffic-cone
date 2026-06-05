//! Data types that map to database rows.
//! All types that contain key material implement Zeroize.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A TLS client certificate (public material only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cert {
    pub id:          String,
    pub label:       String,
    pub cert_der:    Vec<u8>,
    pub fingerprint: String,
    pub subject:     String,
    pub issuer:      String,
    pub not_before:  i64,
    pub not_after:   i64,
    pub created_at:  i64,
}

/// An encrypted private key blob for a TLS cert.
/// The plaintext key never appears in this struct.
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub id:        String,
    pub cert_id:   String,
    pub algorithm: KeyAlgorithm,
    pub key_enc:   Vec<u8>,   // AES-256-GCM ciphertext
    pub key_salt:  Vec<u8>,   // Argon2id salt
    pub key_nonce: Vec<u8>,   // GCM nonce
}

/// A decrypted private key — lives in memory only, zeroed on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextKey {
    pub algorithm: KeyAlgorithm,
    pub key_bytes: Vec<u8>,
}

/// An encrypted SSH keypair.
#[derive(Debug, Clone)]
pub struct SshKey {
    pub id:         String,
    pub label:      String,
    pub public_key: String,    // OpenSSH wire format
    pub algorithm:  SshAlgorithm,
    pub key_enc:    Vec<u8>,
    pub key_salt:   Vec<u8>,
    pub key_nonce:  Vec<u8>,
    pub created_at: i64,
}

/// A CA certificate (trust anchor).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaCert {
    pub id:          String,
    pub label:       String,
    pub cert_pem:    String,
    pub fingerprint: String,
    pub subject:     String,
    pub not_after:   i64,
    pub system_file: Option<String>,
    pub created_at:  i64,
}

/// A registered application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id:            String,
    pub label:         String,
    pub exe_path:      String,
    pub exe_hash:      String,   // SHA-256 hex
    pub registered_at: i64,
}

/// A TLS routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id:           String,
    pub cert_id:      String,
    pub app_id:       Option<String>,
    pub match_type:   MatchType,
    pub pattern:      Option<String>,
    pub require_both: bool,
    pub priority:     i64,
    pub created_at:   i64,
}

/// An SSH routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRoute {
    pub id:           String,
    pub ssh_key_id:   String,
    pub app_id:       Option<String>,
    pub host_pattern: Option<String>,
    pub created_at:   i64,
}

/// A binary integrity record (AIDE-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRecord {
    pub id:          String,
    pub component:   String,   // 'coned', 'libcone.so', 'cone'
    pub path:        String,
    pub sha256:      String,
    pub version:     String,
    pub recorded_at: i64,
    pub verified_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    EcP256,
    EcP384,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchType {
    Hostname,
    Ip,
    IpCidr,
}
