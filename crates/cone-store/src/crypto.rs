//! Cryptographic primitives for Traffic Cone.
//!
//! Key derivation, encryption/decryption of key material,
//! and signing operations. All plaintext key material is
//! handled in Zeroize-wrapped types and zeroed after use.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use crate::error::StoreError;

/// Argon2id parameters — conservative defaults suitable for a desktop daemon.
/// Memory: 64MB, iterations: 3, parallelism: 1.
pub const ARGON2_MEMORY_KB: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const KEY_LEN: usize = 32; // 256 bits
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Derive a 256-bit key from a passphrase and salt using Argon2id.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let params = Params::new(ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_LEN))
        .map_err(|e| StoreError::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| StoreError::Crypto(e.to_string()))?;

    Ok(key)
}

/// Generate a random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt plaintext key material with AES-256-GCM.
/// Returns (ciphertext, salt, nonce) — all three must be stored.
pub fn encrypt_key(
    key_bytes: &[u8],
    passphrase: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), StoreError> {
    let salt = random_salt();
    let nonce_bytes = random_nonce();

    let derived = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(derived.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, key_bytes)
        .map_err(|e| StoreError::Crypto(e.to_string()))?;

    Ok((ciphertext, salt.to_vec(), nonce_bytes.to_vec()))
}

/// Decrypt key material with AES-256-GCM.
/// Returns plaintext bytes in a Zeroizing wrapper.
pub fn decrypt_key(
    ciphertext: &[u8],
    salt: &[u8],
    nonce_bytes: &[u8],
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let derived = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(derived.as_ref()));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StoreError::WrongPassphrase)?;

    Ok(Zeroizing::new(plaintext))
}

/// Compute the SHA-256 hash of a file at the given path.
pub fn hash_file(path: &str) -> Result<String, StoreError> {
    let bytes = std::fs::read(path)?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

/// Compute the SHA-256 hash of arbitrary bytes.
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
