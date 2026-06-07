//! IPC client for cone-p11 → coned communication.
//!
//! Connects to coned's abstract Unix socket, sends signing requests,
//! and receives signatures. Private key material never passes through
//! this code — we send data to sign and receive the signature back.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

/// The abstract socket name — must match coned's SOCKET_NAME exactly.
const SOCKET_NAME: &str = "\x00traffic-cone-daemon";

/// A cached connection to coned.
/// Lazily initialised on first use, reconnected if dropped.
static CONNECTION: Mutex<Option<UnixStream>> = Mutex::new(None);

/// A certificate returned from coned for PKCS#11 object enumeration.
#[derive(Debug, Clone)]
pub struct P11Cert {
    pub id:          Vec<u8>,   // object handle bytes
    pub label:       String,
    pub cert_der:    Vec<u8>,
    pub fingerprint: String,
}

/// Connect to coned, reusing the cached connection if available.
fn get_connection() -> Result<(), P11Error> {
    let mut guard = CONNECTION.lock().map_err(|_| P11Error::Unavailable)?;

    if guard.is_none() {
        let stream = UnixStream::connect(SOCKET_NAME)
            .map_err(|_| P11Error::Unavailable)?;
        *guard = Some(stream);
    }

    Ok(())
}

/// Disconnect from coned — called from C_Finalize.
pub fn disconnect() {
    if let Ok(mut guard) = CONNECTION.lock() {
        *guard = None;
    }
}

/// Request the list of available certificates from coned.
pub fn list_certs() -> Result<Vec<P11Cert>, P11Error> {
    send_request(&Request::ListCerts)?;
    match recv_response()? {
        Response::Certs { certs } => {
            Ok(certs.into_iter().enumerate().map(|(i, c)| P11Cert {
                id:          vec![i as u8],
                label:       c.label,
                cert_der:    c.cert_der,
                fingerprint: c.fingerprint,
            }).collect())
        }
        Response::Error { message } => {
            Err(P11Error::DaemonError(message))
        }
        _ => Err(P11Error::Protocol),
    }
}

/// Request a signing operation from coned.
///
/// `data` is the TLS handshake hash to sign.
/// Returns the raw signature bytes.
pub fn sign(pid: u32, data: Vec<u8>) -> Result<Vec<u8>, P11Error> {
    send_request(&Request::Sign { pid, data })?;
    match recv_response()? {
        Response::Signature { signature, .. } => Ok(signature),
        Response::Error { message } => Err(P11Error::DaemonError(message)),
        _ => Err(P11Error::Protocol),
    }
}

// ---------------------------------------------------------------------------
// Wire protocol — must match coned's IPC framing exactly
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum Request {
    ListCerts,
    Sign { pid: u32, data: Vec<u8> },
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum Response {
    Certs    { certs: Vec<CertInfo> },
    Signature { cert_id: String, signature: Vec<u8> },
    Error    { message: String },
    Pong,
    Ok,
    Status   { locked: bool, cert_count: usize },
}

#[derive(serde::Deserialize)]
struct CertInfo {
    id:          String,
    label:       String,
    cert_der:    Vec<u8>,
    fingerprint: String,
}

fn send_request(req: &Request) -> Result<(), P11Error> {
    get_connection()?;
    let mut guard = CONNECTION.lock().map_err(|_| P11Error::Unavailable)?;
    let stream = guard.as_mut().ok_or(P11Error::Unavailable)?;

    let json = serde_json::to_vec(req).map_err(|_| P11Error::Protocol)?;
    let len  = (json.len() as u32).to_be_bytes();

    stream.write_all(&len).map_err(|_| {
        // Connection dropped — clear it so next call reconnects
        P11Error::Unavailable
    })?;
    stream.write_all(&json).map_err(|_| P11Error::Unavailable)?;

    Ok(())
}

fn recv_response() -> Result<Response, P11Error> {
    let mut guard = CONNECTION.lock().map_err(|_| P11Error::Unavailable)?;
    let stream = guard.as_mut().ok_or(P11Error::Unavailable)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|_| P11Error::Unavailable)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).map_err(|_| P11Error::Unavailable)?;

    serde_json::from_slice(&buf).map_err(|_| P11Error::Protocol)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum P11Error {
    /// coned is not running or not reachable
    Unavailable,
    /// Protocol error — unexpected response
    Protocol,
    /// coned returned an error message
    DaemonError(String),
}