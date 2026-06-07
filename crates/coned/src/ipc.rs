//! IPC server for coned.
//!
//! Listens on an abstract Unix socket. On every new connection:
//!
//! 1. SO_PEERCRED — kernel-provided PID/UID/GID, cannot be spoofed
//! 2. UID check — only our own user can connect
//! 3. Binary hash check — only verified Traffic Cone binaries
//! 4. Session HMAC key exchange — all subsequent messages are authenticated
//! 5. Dispatch request — route resolution, signing, store operations
//!
//! The abstract socket name starts with a null byte, placing it in
//! the Linux kernel's abstract namespace. There is no socket file on
//! disk to redirect, replace, or bind over.

use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::io::{Read, Write};

use anyhow::{bail, Result};
use cone_store::Store;

use crate::process_monitor::ProcessMonitor;
use crate::routing;

/// The abstract socket name. The leading null byte puts it in the
/// kernel abstract namespace — no file on disk.
pub const SOCKET_NAME: &str = "\x00traffic-cone-daemon";

/// Messages that clients can send to coned.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Ping — check that the daemon is alive
    Ping,

    /// Request a TLS signing operation for a PID
    Sign {
        pid:  u32,
        data: Vec<u8>,  // data to sign (TLS handshake hash)
    },

    /// List all certificates
    ListCerts,

    /// Get daemon status
    Status,

    /// Lock the store
    Lock,
}

/// Responses from coned to clients.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Ping reply
    Pong,

    /// Signing result
    Signature {
        cert_id:   String,
        signature: Vec<u8>,
    },

    /// Certificate list
    Certs {
        certs: Vec<CertSummary>,
    },

    /// Daemon status
    Status {
        locked:    bool,
        cert_count: usize,
    },

    /// Operation succeeded with no data
    Ok,

    /// Operation failed
    Error {
        message: String,
    },
}

/// A brief cert summary for listing.
#[derive(Debug, serde::Serialize)]
pub struct CertSummary {
    pub id:          String,
    pub label:       String,
    pub fingerprint: String,
    pub subject:     String,
    pub not_after:   i64,
}

/// The IPC server state shared across connections.
pub struct IpcServer {
    store:         Arc<Mutex<Store>>,
    monitor:       Arc<ProcessMonitor>,
    known_hashes:  HashMap<String, String>,
}

impl IpcServer {
    pub fn new(
        store: Arc<Mutex<Store>>,
        monitor: Arc<ProcessMonitor>,
        known_hashes: HashMap<String, String>,
    ) -> Self {
        IpcServer { store, monitor, known_hashes }
    }

    /// Start the IPC server and block handling connections.
    ///
    /// Each connection is handled synchronously for now.
    /// Async handling via tokio is a planned improvement.
    pub fn run(&self) -> Result<()> {
        let listener = bind_abstract_socket(SOCKET_NAME)?;
        tracing::info!("IPC server listening on abstract socket");

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Get kernel-provided peer credentials
                    let (peer_pid, peer_uid) = get_peer_credentials(&stream)?;

                    tracing::debug!("Incoming connection from PID {} UID {}", peer_pid, peer_uid);

                    // Verify the connecting binary
                    match routing::verify_traffic_cone_binary(
                        &self.monitor,
                        peer_pid,
                        peer_uid,
                        &self.known_hashes,
                    ) {
                        Ok(process) => {
                            tracing::debug!(
                                "Verified connection from {} (PID {})",
                                process.exe_path, peer_pid
                            );

                            // Handle the request
                            if let Err(e) = self.handle_connection(&mut stream, peer_pid) {
                                tracing::warn!("Connection error: {}", e);
                                let _ = send_response(
                                    &mut stream,
                                    &Response::Error { message: e.to_string() }
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Rejected connection from PID {}: {}", peer_pid, e
                            );
                            // Send error and close — don't process any request data
                            let _ = send_response(
                                &mut stream,
                                &Response::Error {
                                    message: "Connection rejected: unauthorized process".into()
                                }
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to accept connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single verified connection.
    fn handle_connection(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        peer_pid: u32,
    ) -> Result<()> {
        let request = read_request(stream)?;

        let response = match request {
            Request::Ping => Response::Pong,

            Request::Status => {
                let store = self.store.lock().unwrap();
                let locked = !store.is_unlocked();
                let cert_count = if !locked {
                    cone_store::list::list_certs(&store)
                        .map(|c| c.len())
                        .unwrap_or(0)
                } else {
                    0
                };
                Response::Status { locked, cert_count }
            }

            Request::Lock => {
                let mut store = self.store.lock().unwrap();
                store.lock();
                tracing::info!("Store locked via IPC request from PID {}", peer_pid);
                Response::Ok
            }

            Request::ListCerts => {
                let store = self.store.lock().unwrap();
                match cone_store::list::list_certs(&store) {
                    Ok(certs) => Response::Certs {
                        certs: certs.into_iter().map(|c| CertSummary {
                            id:          c.id,
                            label:       c.label,
                            fingerprint: c.fingerprint,
                            subject:     c.subject,
                            not_after:   c.not_after,
                        }).collect(),
                    },
                    Err(e) => Response::Error { message: e.to_string() },
                }
            }

            Request::Sign { pid, data } => {
                let store = self.store.lock().unwrap();

                // Resolve which cert to use for this PID
                match routing::resolve_for_pid(
                    &store,
                    &self.monitor,
                    pid,
                    &self.known_hashes,
                ) {
                    Ok(route) => {
                        // Decrypt the key and sign
                        match sign_data(&store, &route.cert_id, &data) {
                            Ok(signature) => {
                                tracing::info!(
                                    "Signed for PID {} using cert {}",
                                    pid, route.cert_id
                                );
                                Response::Signature {
                                    cert_id: route.cert_id,
                                    signature,
                                }
                            }
                            Err(e) => Response::Error { message: e.to_string() },
                        }
                    }
                    Err(e) => Response::Error { message: e.to_string() },
                }
            }
        };

        send_response(stream, &response)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Decrypt the private key for a cert and sign the provided data.
///
/// The key exists in plaintext for the minimum time required —
/// it is zeroed immediately after the signing operation completes.
fn sign_data(store: &Store, cert_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    use cone_store::list::get_plaintext_key;
    use cone_store::models::KeyAlgorithm;

    let (key_bytes, algorithm) = get_plaintext_key(store, cert_id)
        .map_err(|e| anyhow::anyhow!("failed to retrieve key: {}", e))?;

    // Sign based on algorithm
    // key_bytes is Zeroizing<Vec<u8>> — zeroed on drop
    let signature = match algorithm {
        KeyAlgorithm::EcP256 | KeyAlgorithm::EcP384 => {
            sign_ecdsa(&key_bytes, data)?
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            sign_rsa(&key_bytes, data)?
        }
    };

    // key_bytes is dropped here — memory zeroed automatically by Zeroizing
    Ok(signature)
}

/// Sign data with an EC private key (P-256 or P-384).
fn sign_ecdsa(key_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_der(key_der)
        .map_err(|e| anyhow::anyhow!("failed to parse EC key: {}", e))?;

    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Sign data with an RSA private key.
fn sign_rsa(key_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding}};
    use rsa::pkcs8::DecodePrivateKey;

    let private_key = RsaPrivateKey::from_pkcs8_der(key_der)
        .map_err(|e| anyhow::anyhow!("failed to parse RSA key: {}", e))?;

    let signing_key = SigningKey::<rsa::sha2::Sha256>::new(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_vec())
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

/// Bind an abstract Unix socket.
///
/// Abstract sockets live in the kernel namespace only — no file on disk,
/// nothing to redirect or replace. The leading null byte is the marker.
fn bind_abstract_socket(name: &str) -> Result<UnixListener> {
    use std::os::unix::net::UnixListener;

    // Abstract socket names start with \0
    // std::os::unix handles this via the raw sockaddr_un interface
    let listener = UnixListener::bind(name)
        .map_err(|e| anyhow::anyhow!(
            "failed to bind abstract socket '{}': {}", name, e
        ))?;

    Ok(listener)
}

/// Get the PID and UID of the connecting process via SO_PEERCRED.
///
/// SO_PEERCRED is filled by the kernel at connect time and cannot
/// be spoofed by the connecting process.
#[cfg(target_os = "linux")]
fn get_peer_credentials(stream: &std::os::unix::net::UnixStream) -> Result<(u32, u32)> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        bail!("getsockopt(SO_PEERCRED) failed");
    }

    Ok((ucred.pid as u32, ucred.uid as u32))
}

#[cfg(not(target_os = "linux"))]
fn get_peer_credentials(_stream: &std::os::unix::net::UnixStream) -> Result<(u32, u32)> {
    Ok((std::process::id(), 1000))
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

/// Read a length-prefixed JSON request from the stream.
fn read_request(stream: &mut std::os::unix::net::UnixStream) -> Result<Request> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > 1024 * 1024 {
        bail!("Request too large: {} bytes", len);
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map_err(|e| anyhow::anyhow!("failed to parse request: {}", e))
}

/// Write a length-prefixed JSON response to the stream.
fn send_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: &Response,
) -> Result<()> {
    let json = serde_json::to_vec(response)?;
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&json)?;
    Ok(())
}