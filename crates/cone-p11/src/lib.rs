//! cone-p11 — PKCS#11 module for Traffic Cone.
//!
//! Compiled as a cdylib: libcone.so
//!
//! This module is intentionally thin. Its only job is to expose a
//! spec-compliant PKCS#11 C ABI and forward all meaningful operations
//! to coned over an abstract Unix socket.
//!
//! Private key material never enters this crate.
//! All signing operations are performed inside coned.
//! This module receives only signatures.

// PKCS#11 requires specific C-ABI entry points.
// The cryptoki crate provides the type definitions.
// Full implementation is TODO — stubs return CKR_OK or
// CKR_FUNCTION_NOT_SUPPORTED as appropriate.

mod ipc;
mod pkcs11_impl;

pub use pkcs11_impl::*;
