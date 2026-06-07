//! cone-p11 — PKCS#11 module for Traffic Cone.
//!
//! Compiled as a cdylib: libcone.so
//!
//! This module implements the minimum PKCS#11 surface required for
//! TLS client certificate authentication:
//!
//! - C_Initialize / C_Finalize       — connect to / disconnect from coned
//! - C_GetInfo / C_GetSlotList       — module and slot discovery
//! - C_GetSlotInfo / C_GetTokenInfo  — token metadata
//! - C_OpenSession / C_CloseSession  — session lifecycle
//! - C_FindObjectsInit/FindObjects   — certificate enumeration
//! - C_GetAttributeValue             — read cert/key attributes
//! - C_SignInit / C_Sign             — signing operations (the core)
//!
//! Everything else returns CKR_FUNCTION_NOT_SUPPORTED.
//!
//! The TLS stack (GnuTLS/NSS/OpenSSL) calls these functions during
//! a TLS handshake when the server sends a CertificateRequest.
//! We find the matching cert via coned and return a signature.

mod ipc;
mod pkcs11_impl;

pub use pkcs11_impl::*;