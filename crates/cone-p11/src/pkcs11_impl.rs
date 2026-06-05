//! PKCS#11 C ABI stubs.
//!
//! Uses raw C types directly since PKCS#11 is fundamentally a C API.
//! Full implementation comes after cone-store and coned are stable.

use std::os::raw::{c_ulong, c_void};

// PKCS#11 basic types
pub type CK_RV = c_ulong;
pub type CK_VOID_PTR = *mut c_void;

// PKCS#11 return values
pub const CKR_OK: CK_RV = 0;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;

#[no_mangle]
pub extern "C" fn C_Initialize(_p_init_args: CK_VOID_PTR) -> CK_RV {
    // TODO: connect to coned socket, verify identity
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    // TODO: disconnect from coned socket
    CKR_OK
}