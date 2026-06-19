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
// PKCS#11 types
// ---------------------------------------------------------------------------

pub type CK_RV             = c_ulong;
pub type CK_SLOT_ID        = c_ulong;
pub type CK_SESSION_HANDLE = c_ulong;
pub type CK_OBJECT_HANDLE  = c_ulong;
pub type CK_MECHANISM_TYPE = c_ulong;
pub type CK_FLAGS          = c_ulong;
pub type CK_ULONG          = c_ulong;
pub type CK_BBOOL          = c_uchar;
pub type CK_BYTE           = c_uchar;
pub type CK_VOID_PTR       = *mut c_void;
pub type CK_ULONG_PTR      = *mut CK_ULONG;
pub type CK_SLOT_ID_PTR    = *mut CK_SLOT_ID;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR  = *mut CK_OBJECT_HANDLE;
pub type CK_BYTE_PTR       = *mut CK_BYTE;

// Return values
pub const CKR_OK:                     CK_RV = 0;
pub const CKR_GENERAL_ERROR:          CK_RV = 0x00000005;
pub const CKR_ARGUMENTS_BAD:          CK_RV = 0x00000007;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_OBJECT_HANDLE_INVALID:  CK_RV = 0x00000082;

// ---------------------------------------------------------------------------
// Function list structure (required by PKCS#11 spec)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    version: [u8; 2],
    C_Initialize:          Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    C_Finalize:            Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    C_GetInfo:             Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    C_GetFunctionList:     Option<unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV>,
    C_GetSlotList:         Option<unsafe extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_GetSlotInfo:         Option<unsafe extern "C" fn(CK_SLOT_ID, CK_VOID_PTR) -> CK_RV>,
    C_GetTokenInfo:        Option<unsafe extern "C" fn(CK_SLOT_ID, CK_VOID_PTR) -> CK_RV>,
    C_GetMechanismList:    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_VOID_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_GetMechanismInfo:    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_VOID_PTR) -> CK_RV>,
    C_InitToken:           Option<unsafe extern "C" fn(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR) -> CK_RV>,
    C_InitPIN:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_SetPIN:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_OpenSession:         Option<unsafe extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, CK_SESSION_HANDLE_PTR) -> CK_RV>,
    C_CloseSession:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    C_CloseAllSessions:    Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>,
    C_GetSessionInfo:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR) -> CK_RV>,
    C_GetOperationState:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_SetOperationState:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    C_Login:               Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_Logout:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    C_CreateObject:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_CopyObject:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_DestroyObject:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    C_GetObjectSize:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>,
    C_GetAttributeValue:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV>,
    C_SetAttributeValue:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV>,
    C_FindObjectsInit:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV>,
    C_FindObjects:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV>,
    C_FindObjectsFinal:    Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    C_EncryptInit:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_Encrypt:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_EncryptUpdate:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_EncryptFinal:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DecryptInit:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_Decrypt:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DecryptUpdate:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DecryptFinal:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DigestInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR) -> CK_RV>,
    C_Digest:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DigestUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_DigestKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    C_DigestFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_SignInit:            Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_Sign:                Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_SignUpdate:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_SignFinal:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_SignRecoverInit:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_SignRecover:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_VerifyInit:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_Verify:              Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_VerifyUpdate:        Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_VerifyFinal:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_VerifyRecoverInit:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    C_VerifyRecover:       Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DigestEncryptUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DecryptDigestUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_SignEncryptUpdate:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_DecryptVerifyUpdate: Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_GenerateKey:         Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_GenerateKeyPair:     Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_WrapKey:             Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    C_UnwrapKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_DeriveKey:           Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_OBJECT_HANDLE, CK_VOID_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    C_SeedRandom:          Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_GenerateRandom:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    C_GetFunctionStatus:   Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    C_CancelFunction:      Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    C_WaitForSlotEvent:    Option<unsafe extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV>,
}

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

struct ModuleState {
    initialised: bool,
    certs:       Vec<ipc::P11Cert>,
    sign_handle: Option<CK_OBJECT_HANDLE>,
}

static STATE: Mutex<ModuleState> = Mutex::new(ModuleState {
    initialised: false,
    certs:       Vec::new(),
    sign_handle: None,
});

static FIND_POSITION: Mutex<usize> = Mutex::new(0);

// ---------------------------------------------------------------------------
// The function list — populated at compile time, returned by C_GetFunctionList
// ---------------------------------------------------------------------------

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version:               [2, 40],
    C_Initialize:          Some(C_Initialize),
    C_Finalize:            Some(C_Finalize),
    C_GetInfo:             Some(C_GetInfo),
    C_GetFunctionList:     Some(C_GetFunctionList),
    C_GetSlotList:         Some(C_GetSlotList),
    C_GetSlotInfo:         Some(C_GetSlotInfo),
    C_GetTokenInfo:        Some(C_GetTokenInfo),
    C_GetMechanismList:    Some(C_GetMechanismList),
    C_GetMechanismInfo:    Some(C_GetMechanismInfo),
    C_InitToken:           None,
    C_InitPIN:             None,
    C_SetPIN:              None,
    C_OpenSession:         Some(C_OpenSession),
    C_CloseSession:        Some(C_CloseSession),
    C_CloseAllSessions:    Some(C_CloseAllSessions),
    C_GetSessionInfo:      Some(C_GetSessionInfo),
    C_GetOperationState:   None,
    C_SetOperationState:   None,
    C_Login:               Some(C_Login),
    C_Logout:              Some(C_Logout),
    C_CreateObject:        Some(C_CreateObject),
    C_CopyObject:          None,
    C_DestroyObject:       Some(C_DestroyObject),
    C_GetObjectSize:       None,
    C_GetAttributeValue:   Some(C_GetAttributeValue),
    C_SetAttributeValue:   None,
    C_FindObjectsInit:     Some(C_FindObjectsInit),
    C_FindObjects:         Some(C_FindObjects),
    C_FindObjectsFinal:    Some(C_FindObjectsFinal),
    C_EncryptInit:         Some(C_EncryptInit),
    C_Encrypt:             Some(C_Encrypt),
    C_EncryptUpdate:       None,
    C_EncryptFinal:        None,
    C_DecryptInit:         Some(C_DecryptInit),
    C_Decrypt:             Some(C_Decrypt),
    C_DecryptUpdate:       None,
    C_DecryptFinal:        None,
    C_DigestInit:          Some(C_DigestInit),
    C_Digest:              Some(C_Digest),
    C_DigestUpdate:        None,
    C_DigestKey:           None,
    C_DigestFinal:         None,
    C_SignInit:            Some(C_SignInit),
    C_Sign:                Some(C_Sign),
    C_SignUpdate:          None,
    C_SignFinal:           None,
    C_SignRecoverInit:     None,
    C_SignRecover:         None,
    C_VerifyInit:          Some(C_VerifyInit),
    C_Verify:              Some(C_Verify),
    C_VerifyUpdate:        None,
    C_VerifyFinal:         None,
    C_VerifyRecoverInit:   None,
    C_VerifyRecover:       None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate:   None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey:         Some(C_GenerateKey),
    C_GenerateKeyPair:     Some(C_GenerateKeyPair),
    C_WrapKey:             Some(C_WrapKey),
    C_UnwrapKey:           Some(C_UnwrapKey),
    C_DeriveKey:           Some(C_DeriveKey),
    C_SeedRandom:          Some(C_SeedRandom),
    C_GenerateRandom:      Some(C_GenerateRandom),
    C_GetFunctionStatus:   None,
    C_CancelFunction:      None,
    C_WaitForSlotEvent:    None,
};

// ---------------------------------------------------------------------------
// C_GetFunctionList — the required entry point p11-kit looks for
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    pp_function_list: *mut *const CK_FUNCTION_LIST,
) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *pp_function_list = &FUNCTION_LIST as *const CK_FUNCTION_LIST;
    }
    CKR_OK
}

// ---------------------------------------------------------------------------
// Implemented functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn C_Initialize(_p_init_args: CK_VOID_PTR) -> CK_RV {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };
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
pub extern "C" fn C_GetInfo(_p_info: CK_VOID_PTR) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    p_slot_list:    CK_SLOT_ID_PTR,
    pul_count:      CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    unsafe {
        if p_slot_list.is_null() {
            *pul_count = 1;
        } else if *pul_count >= 1 {
            *p_slot_list = 0;
            *pul_count   = 1;
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(_slot_id: CK_SLOT_ID, _p_info: CK_VOID_PTR) -> CK_RV { CKR_OK }

#[repr(C)]
pub struct CK_TOKEN_INFO {
    label:              [u8; 32],
    manufacturer_id:    [u8; 32],
    model:              [u8; 16],
    serial_number:      [u8; 16],
    flags:              CK_FLAGS,
    max_session_count:  CK_ULONG,
    session_count:      CK_ULONG,
    max_rw_session_count: CK_ULONG,
    rw_session_count:   CK_ULONG,
    max_pin_len:        CK_ULONG,
    min_pin_len:        CK_ULONG,
    total_public_memory: CK_ULONG,
    free_public_memory:  CK_ULONG,
    total_private_memory: CK_ULONG,
    free_private_memory:  CK_ULONG,
    hardware_version:   [u8; 2],
    firmware_version:   [u8; 2],
    utc_time:           [u8; 16],
}

fn pad32(s: &str) -> [u8; 32] {
    let mut buf = [b' '; 32];
    let b = s.as_bytes();
    let len = b.len().min(32);
    buf[..len].copy_from_slice(&b[..len]);
    buf
}

fn pad16(s: &str) -> [u8; 16] {
    let mut buf = [b' '; 16];
    let b = s.as_bytes();
    let len = b.len().min(16);
    buf[..len].copy_from_slice(&b[..len]);
    buf
}

#[no_mangle]
pub extern "C" fn C_GetTokenInfo(
    _slot_id: CK_SLOT_ID,
    p_info: CK_VOID_PTR,
) -> CK_RV {
    if p_info.is_null() { return CKR_ARGUMENTS_BAD; }
    let info = CK_TOKEN_INFO {
        label:               pad32("Traffic Cone"),
        manufacturer_id:     pad32("Traffic Cone Project"),
        model:               pad16("cone"),
        serial_number:       pad16("1"),
        flags:               0x0400, // CKF_TOKEN_INITIALIZED
        max_session_count:   0xFFFFFFFF,
        session_count:       0,
        max_rw_session_count: 0xFFFFFFFF,
        rw_session_count:    0,
        max_pin_len:         256,
        min_pin_len:         0,
        total_public_memory: 0xFFFFFFFF,
        free_public_memory:  0xFFFFFFFF,
        total_private_memory: 0xFFFFFFFF,
        free_private_memory:  0xFFFFFFFF,
        hardware_version:    [0, 1],
        firmware_version:    [0, 1],
        utc_time:            [b' '; 16],
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &info as *const CK_TOKEN_INFO as *const u8,
            p_info as *mut u8,
            std::mem::size_of::<CK_TOKEN_INFO>(),
        );
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(_slot_id: CK_SLOT_ID, _p_list: CK_VOID_PTR, pul_count: CK_ULONG_PTR) -> CK_RV {
    if pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    unsafe { *pul_count = 2; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(_slot_id: CK_SLOT_ID, _type_: CK_MECHANISM_TYPE, _p_info: CK_VOID_PTR) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_OpenSession(_slot_id: CK_SLOT_ID, _flags: CK_FLAGS, _p_app: CK_VOID_PTR, _notify: CK_VOID_PTR, ph_session: CK_SESSION_HANDLE_PTR) -> CK_RV {
    if ph_session.is_null() { return CKR_ARGUMENTS_BAD; }
    unsafe { *ph_session = 1; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(_h_session: CK_SESSION_HANDLE) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(_slot_id: CK_SLOT_ID) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_GetSessionInfo(_h_session: CK_SESSION_HANDLE, _p_info: CK_VOID_PTR) -> CK_RV { CKR_FUNCTION_NOT_SUPPORTED }

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(_h_session: CK_SESSION_HANDLE, _p_template: CK_VOID_PTR, _ul_count: CK_ULONG) -> CK_RV {
    if let Ok(mut state) = STATE.lock() {
        state.certs = ipc::list_certs().unwrap_or_default();
    }
    if let Ok(mut pos) = FIND_POSITION.lock() { *pos = 0; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjects(_h_session: CK_SESSION_HANDLE, ph_object: CK_OBJECT_HANDLE_PTR, ul_max: CK_ULONG, pul_count: CK_ULONG_PTR) -> CK_RV {
    if ph_object.is_null() || pul_count.is_null() { return CKR_ARGUMENTS_BAD; }
    let state = match STATE.lock() { Ok(s) => s, Err(_) => return CKR_GENERAL_ERROR };
    let mut pos = match FIND_POSITION.lock() { Ok(p) => p, Err(_) => return CKR_GENERAL_ERROR };
    let mut count = 0u64;
    let max = ul_max as usize;
    while count < max as u64 && *pos < state.certs.len() * 2 {
        unsafe { *ph_object.add(count as usize) = *pos as CK_OBJECT_HANDLE; }
        count += 1;
        *pos  += 1;
    }
    unsafe { *pul_count = count; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(_h_session: CK_SESSION_HANDLE) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(_h_session: CK_SESSION_HANDLE, h_object: CK_OBJECT_HANDLE, _p_template: CK_VOID_PTR, _ul_count: CK_ULONG) -> CK_RV {
    let state = match STATE.lock() { Ok(s) => s, Err(_) => return CKR_GENERAL_ERROR };
    let cert_index = (h_object / 2) as usize;
    if state.certs.get(cert_index).is_none() { return CKR_OBJECT_HANDLE_INVALID; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_SignInit(_h_session: CK_SESSION_HANDLE, _p_mechanism: CK_VOID_PTR, h_key: CK_OBJECT_HANDLE) -> CK_RV {
    let mut state = match STATE.lock() { Ok(s) => s, Err(_) => return CKR_GENERAL_ERROR };
    let cert_index = (h_key / 2) as usize;
    if state.certs.get(cert_index).is_none() { return CKR_OBJECT_HANDLE_INVALID; }
    state.sign_handle = Some(h_key);
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Sign(_h_session: CK_SESSION_HANDLE, p_data: CK_BYTE_PTR, ul_data_len: CK_ULONG, p_signature: CK_BYTE_PTR, pul_signature_len: CK_ULONG_PTR) -> CK_RV {
    if p_data.is_null() || pul_signature_len.is_null() { return CKR_ARGUMENTS_BAD; }
    let state = match STATE.lock() { Ok(s) => s, Err(_) => return CKR_GENERAL_ERROR };
    if state.sign_handle.is_none() { return CKR_GENERAL_ERROR; }
    let data = unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize).to_vec() };
    let pid  = std::process::id();
    drop(state);
    match ipc::sign(pid, data) {
        Ok(signature) => {
            unsafe {
                if p_signature.is_null() {
                    *pul_signature_len = signature.len() as CK_ULONG;
                } else if *pul_signature_len >= signature.len() as CK_ULONG {
                    std::ptr::copy_nonoverlapping(signature.as_ptr(), p_signature, signature.len());
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
// Stubs for functions p11-kit expects to exist but we don't implement
// ---------------------------------------------------------------------------

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