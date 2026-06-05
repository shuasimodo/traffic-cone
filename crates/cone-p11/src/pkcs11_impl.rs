//! PKCS#11 C ABI implementation.
//!
//! Exposes the required C_* entry points. Non-signing functions that
//! Traffic Cone does not implement return CKR_FUNCTION_NOT_SUPPORTED.

use cryptoki::types::*;

// CKR constants — defined by the PKCS#11 spec
pub const CKR_OK: CK_RV = 0;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;

#[no_mangle]
pub extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    // TODO: populate function list pointer
    CKR_OK
}

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

// All unimplemented functions return CKR_FUNCTION_NOT_SUPPORTED
// Full implementation comes after cone-store and coned are stable
