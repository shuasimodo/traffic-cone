//! SSH agent protocol server for coned.
//!
//! Implements the OpenSSH agent protocol (draft-miller-ssh-agent)
//! over an abstract Unix socket. SSH clients connect via $SSH_AUTH_SOCK
//! and Traffic Cone responds exactly as ssh-agent would.
//!
//! Only the messages needed for authentication are implemented:
//! - SSH_AGENTC_REQUEST_IDENTITIES  — list available keys
//! - SSH_AGENTC_SIGN_REQUEST        — sign a challenge
//!
//! All other messages return SSH_AGENT_FAILURE, which is spec-compliant.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use cone_store::Store;

use crate::process_monitor::ProcessMonitor;

/// Abstract socket name for the SSH agent.
/// Exposed to SSH clients via $SSH_AUTH_SOCK.
pub const SSH_AGENT_SOCKET: &str = "\x00traffic-cone-ssh-agent";

// SSH agent message types (from the protocol spec)
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8       = 13;

const SSH_AGENT_FAILURE: u8             = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8   = 12;
const SSH_AGENT_SIGN_RESPONSE: u8       = 14;

// Sign request flags
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// The SSH agent server.
pub struct SshAgentServer {
    store:   Arc<Mutex<Store>>,
    monitor: Arc<ProcessMonitor>,
}

impl SshAgentServer {
    pub fn new(store: Arc<Mutex<Store>>, monitor: Arc<ProcessMonitor>) -> Self {
        SshAgentServer { store, monitor }
    }

    /// Start the SSH agent server and block handling connections.
    pub fn run(&self) -> Result<()> {
        let listener = bind_abstract_socket(SSH_AGENT_SOCKET)?;
        tracing::info!("SSH agent listening on abstract socket");

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    loop {
                        match self.handle_message(&mut stream) {
                            Ok(true)  => continue,   // keep connection alive
                            Ok(false) => break,      // client closed connection
                            Err(e) => {
                                tracing::debug!("SSH agent connection error: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("SSH agent accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle one SSH agent message from the stream.
    /// Returns Ok(true) to keep the connection open, Ok(false) to close.
    fn handle_message(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
    ) -> Result<bool> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(false); // client disconnected cleanly
            }
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 256 * 1024 {
            bail!("invalid SSH agent message length: {}", len);
        }

        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;

        if msg.is_empty() {
            return Ok(true);
        }

        let msg_type = msg[0];
        let payload  = &msg[1..];

        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                self.handle_request_identities()
            }
            SSH_AGENTC_SIGN_REQUEST => {
                self.handle_sign_request(payload)
            }
            _ => {
                // Unknown message — return failure per spec
                tracing::debug!("Unknown SSH agent message type: {}", msg_type);
                Ok(vec![SSH_AGENT_FAILURE])
            }
        };

        let response_bytes = response.unwrap_or_else(|e| {
            tracing::debug!("SSH agent error: {}", e);
            vec![SSH_AGENT_FAILURE]
        });

        // Write length-prefixed response
        let len = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(&response_bytes)?;

        Ok(true)
    }

    /// Handle SSH_AGENTC_REQUEST_IDENTITIES.
    ///
    /// Returns a list of all available SSH public keys.
    /// Format: SSH_AGENT_IDENTITIES_ANSWER + uint32(count) + (string key_blob, string comment)*
    fn handle_request_identities(&self) -> Result<Vec<u8>> {
        let store = self.store.lock().unwrap();
        let keys  = cone_store::list::list_ssh_keys(&store)
            .unwrap_or_default();

        let mut buf = vec![SSH_AGENT_IDENTITIES_ANSWER];

        // Number of keys
        let count = keys.len() as u32;
        buf.extend_from_slice(&count.to_be_bytes());

        for key in &keys {
            // key_blob is the OpenSSH wire format public key
            let key_bytes = key.public_key.as_bytes();
            write_string(&mut buf, key_bytes);

            // Comment is the label
            write_string(&mut buf, key.label.as_bytes());
        }

        Ok(buf)
    }

    /// Handle SSH_AGENTC_SIGN_REQUEST.
    ///
    /// Format: string key_blob, string data, uint32 flags
    /// We find the key matching the blob, sign the data, return the signature.
    fn handle_sign_request(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(payload);

        let key_blob = read_string(&mut cursor)?;
        let data     = read_string(&mut cursor)?;
        let flags    = read_u32(&mut cursor)?;

        // Find the SSH key matching this public key blob
        let store = self.store.lock().unwrap();
        let keys  = cone_store::list::list_ssh_keys(&store)?;

        let matching_key = keys.iter().find(|k| {
            k.public_key.as_bytes() == key_blob.as_slice()
        });

        let key = match matching_key {
            Some(k) => k,
            None => {
                tracing::debug!("SSH sign request for unknown key");
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
        };

        // Decrypt the private key
        let plaintext = cone_store::list::get_ssh_plaintext_key(&store, &key.label)
            .map_err(|e| anyhow::anyhow!("failed to retrieve SSH key: {}", e))?;

        // Sign the data
        let (sig_type, signature) = sign_ssh_data(
            &plaintext,
            &data,
            key.algorithm,
            flags,
        )?;

        // Build SSH_AGENT_SIGN_RESPONSE
        // Format: SSH_AGENT_SIGN_RESPONSE + string(sig_type + signature)
        let mut sig_blob = Vec::new();
        write_string(&mut sig_blob, sig_type.as_bytes());
        write_string(&mut sig_blob, &signature);

        let mut buf = vec![SSH_AGENT_SIGN_RESPONSE];
        write_string(&mut buf, &sig_blob);

        tracing::info!("SSH sign request completed for key '{}'", key.label);

        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// SSH signing
// ---------------------------------------------------------------------------

/// Sign data using an SSH private key.
/// Returns (signature_type_string, signature_bytes).
fn sign_ssh_data(
    key_der: &[u8],
    data: &[u8],
    algorithm: cone_store::models::SshAlgorithm,
    flags: u32,
) -> Result<(String, Vec<u8>)> {
    use cone_store::models::SshAlgorithm;

    match algorithm {
        SshAlgorithm::Ed25519 => sign_ed25519(key_der, data),
        SshAlgorithm::EcdsaP256 => sign_ecdsa_p256(key_der, data),
        SshAlgorithm::Rsa4096 => {
            // RSA with SHA-256 or SHA-512 based on flags
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                sign_rsa_ssh(key_der, data, true)
            } else {
                sign_rsa_ssh(key_der, data, false)
            }
        }
    }
}

fn sign_ed25519(key_der: &[u8], data: &[u8]) -> Result<(String, Vec<u8>)> {
    use ed25519_dalek::{SigningKey, Signer};

    // ed25519 keys are 32 bytes — extract from PKCS#8
    if key_der.len() < 32 {
        bail!("ed25519 key too short");
    }

    // The raw key bytes are the last 32 bytes of the PKCS#8 structure
    let key_bytes: [u8; 32] = key_der[key_der.len() - 32..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract ed25519 key bytes"))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature   = signing_key.sign(data);

    Ok(("ssh-ed25519".to_string(), signature.to_bytes().to_vec()))
}

fn sign_ecdsa_p256(key_der: &[u8], data: &[u8]) -> Result<(String, Vec<u8>)> {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_der(key_der)
        .map_err(|e| anyhow::anyhow!("failed to parse P-256 key: {}", e))?;

    let signature: Signature = signing_key.sign(data);

    Ok(("ecdsa-sha2-nistp256".to_string(), signature.to_der().as_bytes().to_vec()))
}

fn sign_rsa_ssh(key_der: &[u8], data: &[u8], use_sha512: bool) -> Result<(String, Vec<u8>)> {
    use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding}};
    use rsa::pkcs8::DecodePrivateKey;

    let private_key = RsaPrivateKey::from_pkcs8_der(key_der)
        .map_err(|e| anyhow::anyhow!("failed to parse RSA key: {}", e))?;

    if use_sha512 {
        let signing_key = SigningKey::<rsa::sha2::Sha512>::new(private_key);
        let sig = signing_key.sign(data);
        Ok(("rsa-sha2-512".to_string(), sig.to_vec()))
    } else {
        let signing_key = SigningKey::<rsa::sha2::Sha256>::new(private_key);
        let sig = signing_key.sign(data);
        Ok(("rsa-sha2-256".to_string(), sig.to_vec()))
    }
}

// ---------------------------------------------------------------------------
// Wire format helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed byte string (SSH wire format).
fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(data);
}

/// Read a length-prefixed byte string from a cursor.
fn read_string(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = read_u32(cursor)? as usize;
    if len > 256 * 1024 {
        bail!("SSH string too large: {}", len);
    }
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a big-endian u32 from a cursor.
fn read_u32(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Bind an abstract Unix socket.
fn bind_abstract_socket(name: &str) -> Result<UnixListener> {
    UnixListener::bind(name)
        .map_err(|e| anyhow::anyhow!("failed to bind SSH agent socket: {}", e))
}