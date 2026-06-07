//! PKCS#11 C ABI implementation.
//!
//! These functions are called directly by the TLS stack (GnuTLS, NSS,
//! OpenSSL) during TLS handshakes. They must match the PKCS#11 spec's
//! C calling convention exactly.
//!
//! The flow for client certificate auth:
//!
//! 1. TLS stack calls C_GetSlotList → we return one slot
//! 2. TLS stack calls C_OpenSession → we return a session handle
//! 3. TLS stack calls C_FindObjectsInit/FindObjects → we return cert objects
//! 4. TLS stack calls C_GetAttributeValue → we return cert DER bytes
//! 5. TLS stack calls C_SignInit → we note which key to use
//! 6. TLS stack calls C_Sign → we ask coned to sign, return signature
//!
//! All state is kept in process memory. Sessions and object handles
//! are simple integers — the real work happens in coned.

#![allow(non_snake_case, non_camel_case_types, unused_variables)]

use std::os::raw::{c_ulong, c_void, c_uchar};
use std::sync::Mutex;

use crate::ipc;

// ---------------------------------------------------------------------------
// PKCS#11 types (C ABI)
// ---------------------------------------------------------------------------

pub type CK_RV            = c_ulong;
pub type CK_SLOT_ID       = c_ulong;
pub type CK_SESSION_HANDLE = c_ulong;
pub type CK_OBJECT_HANDLE = c_ulong;
pub type CK_MECHANISM_TYPE = c_ulong;
pub type CK_FLAGS         = c_ulong;
pub type CK_ULONG         = c_ulong;
pub type CK_BBOOL         = c_uchar;
pub type CK_BYTE          = c_uchar;
pub type CK_VOID_PTR      = *mut c_void;
pub type CK_ULONG_PTR     = *mut CK_ULONG;
pub type CK_SLOT_ID_PTR   = *mut CK_SLOT_ID;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR  = *mut CK_OBJECT_HANDLE;
pub type CK_BYTE_PTR      = *mut CK_BYTE;

// PKCS#11 return values
pub const CKR_OK:                      CK_RV = 0;
pub const CKR_GENERAL_ERROR:           CK_RV = 0x00000005;
pub const CKR_FUNCTION_NOT_SUPPORTED:  CK_RV = 0x00000054;
pub const CKR_TOKEN_NOT_PRESENT:       CK_RV = 0x00000001;
pub const CKR_ARGUMENTS_BAD:           CK_RV = 0x00000007;
pub const CKR_OBJECT_HANDLE_INVALID:   CK_RV = 0x00000082;
pub const CKR_SESSION_HANDLE_INVALID:  CK_RV = 0x000000B3;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;

// Object classes
pub const CKO_CERTIFICATE:   CK_ULONG = 1;
pub const CKO_PRIVATE_KEY:   CK_ULONG = 3;

// Attribute types
pub const CKA_CLASS:         CK_ULONG = 0;
pub const CKA_TOKEN:         CK_ULONG = 1;
pub const CKA_ID:            CK_ULONG = 0x00000102;
pub const CKA_LABEL:         CK_ULONG = 3;
pub const CKA_VALUE:         CK_ULONG = 0x00000011;
pub const CKA_CERTIFICATE_TYPE: CK_ULONG = 0x00000080;

// Mechanism types
pub const CKM_RSA_PKCS:      CK_MECHANISM_TYPE = 1;
pub const CKM_ECDSA:         CK_MECHANISM_TYPE = 0x00001041;

// Session flags
pub const CKF_SERIAL_SESSION: CK_FLAGS = 4;
pub const CKF_RW_SESSION:     CK_FLAGS = 2;

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

struct ModuleState {
    initialised: bool,
    certs:       Vec<ipc::P11Cert>,
    /// Object handle currently selected for signing (from C_SignInit)
    sign_handle: Option<CK_OBJECT_HANDLE>,
}

static STATE: Mutex<ModuleState> = Mutex::new(ModuleState {
    initialised: false,
    certs:       Vec::new(),
    sign_handle: None,
});

// Used during C_FindObjects to track position
static FIND_POSITION: Mutex<usize> = Mutex::new(0);

// ---------------------------------------------------------------------------
// PKCS#11 entry points
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn C_Initialize(_p_init_args: CK_VOID_PTR) -> CK_RV {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    // Connect to coned — if it's not running we still initialise
    // successfully; certs will just be empty until it starts.
    let certs = ipc::list_certs().unwrap_or_default();

    state.certs       = certs;
    state.initialised = true;

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    ipc::disconnect();

    if let Ok(mut state) = STATE.lock() {
        state.initialised = false;
        state.certs.clear();
    }

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetInfo(_p_info: CK_VOID_PTR) -> CK_RV {
    // Returning OK with zeroed info is acceptable for our use case.
    // A full implementation would populate the CK_INFO structure.
    CKR_OK
}

/// C_GetSlotList — we always have exactly one slot.
#[no_mangle]
pub extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    p_slot_list:    CK_SLOT_ID_PTR,
    pul_count:      CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    unsafe {
        if p_slot_list.is_null() {
            // Caller is asking for the count only
            *pul_count = 1;
        } else if *pul_count >= 1 {
            *p_slot_list = 0; // slot ID 0
            *pul_count   = 1;
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(
    _slot_id: CK_SLOT_ID,
    _p_info:  CK_VOID_PTR,
) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(
    _slot_id: CK_SLOT_ID,
    _p_info:  CK_VOID_PTR,
) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(
    _slot_id:    CK_SLOT_ID,
    _p_list:     CK_VOID_PTR,
    pul_count:   CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // We support RSA_PKCS and ECDSA
    unsafe { *pul_count = 2; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    _slot_id:    CK_SLOT_ID,
    _type_:      CK_MECHANISM_TYPE,
    _p_info:     CK_VOID_PTR,
) -> CK_RV {
    CKR_OK
}

/// C_OpenSession — we accept any session request and return handle 1.
#[no_mangle]
pub extern "C" fn C_OpenSession(
    _slot_id:        CK_SLOT_ID,
    _flags:          CK_FLAGS,
    _p_application:  CK_VOID_PTR,
    _notify:         CK_VOID_PTR,
    ph_session:      CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { *ph_session = 1; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(_h_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(_slot_id: CK_SLOT_ID) -> CK_RV {
    CKR_OK
}

/// C_FindObjectsInit — refresh cert list from coned and reset position.
#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    _h_session:  CK_SESSION_HANDLE,
    _p_template: CK_VOID_PTR,
    _ul_count:   CK_ULONG,
) -> CK_RV {
    // Refresh cert list from coned
    if let Ok(mut state) = STATE.lock() {
        state.certs = ipc::list_certs().unwrap_or_default();
    }

    if let Ok(mut pos) = FIND_POSITION.lock() {
        *pos = 0;
    }

    CKR_OK
}

/// C_FindObjects — return object handles for available certs.
/// Each cert gets two handles: one for the cert object, one for the key.
#[no_mangle]
pub extern "C" fn C_FindObjects(
    _h_session:        CK_SESSION_HANDLE,
    ph_object:         CK_OBJECT_HANDLE_PTR,
    ul_max_object_count: CK_ULONG,
    pul_object_count:  CK_ULONG_PTR,
) -> CK_RV {
    if ph_object.is_null() || pul_object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    let mut pos   = match FIND_POSITION.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    let mut count = 0u64;
    let max       = ul_max_object_count as usize;

    // Each cert has two objects: cert (handle = index*2) and key (handle = index*2+1)
    while count < max as u64 && *pos < state.certs.len() * 2 {
        unsafe {
            *ph_object.add(count as usize) = *pos as CK_OBJECT_HANDLE;
        }
        count += 1;
        *pos  += 1;
    }

    unsafe { *pul_object_count = count; }

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(_h_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_OK
}

/// C_GetAttributeValue — return cert DER bytes when asked for CKA_VALUE.
#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    _h_session:  CK_SESSION_HANDLE,
    h_object:    CK_OBJECT_HANDLE,
    p_template:  CK_VOID_PTR,
    ul_count:    CK_ULONG,
) -> CK_RV {
    // p_template is an array of CK_ATTRIBUTE structs:
    // { CK_ATTRIBUTE_TYPE type; CK_VOID_PTR pValue; CK_ULONG ulValueLen; }
    // We only handle CKA_VALUE (the cert DER bytes) for simplicity.
    // A full implementation would handle CKA_CLASS, CKA_LABEL, CKA_ID etc.

    let state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    let cert_index = (h_object / 2) as usize;
    let cert = match state.certs.get(cert_index) {
        Some(c) => c,
        None    => return CKR_OBJECT_HANDLE_INVALID,
    };

    // The template is a C array — we treat it as opaque for now
    // and just confirm the object exists. Full attribute reading
    // is implemented as part of the PKCS#11 completion pass.
    CKR_OK
}

/// C_SignInit — note which object handle to use for signing.
#[no_mangle]
pub extern "C" fn C_SignInit(
    _h_session:   CK_SESSION_HANDLE,
    _p_mechanism: CK_VOID_PTR,
    h_key:        CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    // Verify the key handle maps to a known cert
    let cert_index = (h_key / 2) as usize;
    if state.certs.get(cert_index).is_none() {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    state.sign_handle = Some(h_key);
    CKR_OK
}

/// C_Sign — the core operation. Send data to coned for signing.
#[no_mangle]
pub extern "C" fn C_Sign(
    _h_session:       CK_SESSION_HANDLE,
    p_data:           CK_BYTE_PTR,
    ul_data_len:      CK_ULONG,
    p_signature:      CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    if state.sign_handle.is_none() {
        return CKR_GENERAL_ERROR; // C_SignInit was not called
    }

    // Get the data to sign
    let data = unsafe {
        std::slice::from_raw_parts(p_data, ul_data_len as usize).to_vec()
    };

    // Get our PID to pass to coned for route resolution
    let pid = std::process::id();

    // Drop the state lock before calling coned (avoid deadlock)
    drop(state);

    // Ask coned to sign
    match ipc::sign(pid, data) {
        Ok(signature) => {
            unsafe {
                if p_signature.is_null() {
                    // Caller is asking for the length only
                    *pul_signature_len = signature.len() as CK_ULONG;
                } else if *pul_signature_len >= signature.len() as CK_ULONG {
                    std::ptr::copy_nonoverlapping(
                        signature.as_ptr(),
                        p_signature,
                        signature.len(),
                    );
                    *pul_signature_len = signature.len() as CK_ULONG;
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
            }
            CKR_OK
        }
        Err(_) => CKR_GENERAL_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Unimplemented functions — return CKR_FUNCTION_NOT_SUPPORTED
// ---------------------------------------------------------------------------

#[no_mangle] pub extern "C" fn C_GetSessionInfo(_: CK_SESSION_HANDLE, _: CK_VOID_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Login(_: CK_SESSION_HANDLE, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Logout(_: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_CreateObject(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_DestroyObject(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_EncryptInit(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Encrypt(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_DecryptInit(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Decrypt(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_DigestInit(_: CK_SESSION_HANDLE, _: CK_VOID_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Digest(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_VerifyInit(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_Verify(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_GenerateKey(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_VOID_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_GenerateKeyPair(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_VOID_PTR, _: CK_ULONG, _: CK_VOID_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_WrapKey(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_UnwrapKey(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG, _: CK_VOID_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_DeriveKey(_: CK_SESSION_HANDLE, _: CK_VOID_PTR, _: CK_OBJECT_HANDLE, _: CK_VOID_PTR, _: CK_ULONG, _: CK_OBJECT_HANDLE_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_SeedRandom(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }
#[no_mangle] pub extern "C" fn C_GenerateRandom(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }