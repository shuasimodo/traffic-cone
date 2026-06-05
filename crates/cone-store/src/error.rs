use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("wrong passphrase or corrupted database")]
    WrongPassphrase,

    #[error("store is locked — call unlock() first")]
    Locked,

    #[error("integrity check failed: {0}")]
    IntegrityFailure(String),

    #[error("import error: {0}")]
    Import(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
