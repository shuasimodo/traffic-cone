//! IPC client for the cone CLI.
//!
//! Connects to coned's abstract Unix socket and sends requests.
//! Used for commands that need the live daemon (status, lock, list, sign).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum Request {
    Ping,
    Sign { pid: u32, data: Vec<u8> },
    ListCerts,
    Status,
    Lock,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    Pong,
    Signature { cert_id: String, signature: Vec<u8> },
    Certs { certs: Vec<CertSummary> },
    Status { locked: bool, cert_count: usize },
    Ok,
    Error { message: String },
}

#[derive(Debug, Deserialize)]
pub struct CertSummary {
    pub id:          String,
    pub label:       String,
    pub fingerprint: String,
    pub subject:     String,
    pub not_after:   i64,
}

pub struct IpcClient {
    stream: UnixStream,
}

/// Status response from coned
pub struct DaemonStatus {
    pub locked:     bool,
    pub cert_count: usize,
}

impl IpcClient {
    /// Connect to the coned abstract Unix socket.
    pub fn connect() -> Result<Self> {
        let stream = UnixStream::connect("\x00traffic-cone-daemon")
            .context(
                "Failed to connect to coned. Is the Traffic Cone daemon running?\n\
                 Start it with: systemctl --user start coned"
            )?;
        Ok(IpcClient { stream })
    }

    /// Send a ping and verify the daemon responds.
    pub fn ping(&mut self) -> Result<()> {
        self.send(&Request::Ping)?;
        match self.recv()? {
            Response::Pong => Ok(()),
            other => bail!("Unexpected response to ping: {:?}", other),
        }
    }

    /// Get daemon status.
    pub fn status(&mut self) -> Result<DaemonStatus> {
        self.send(&Request::Status)?;
        match self.recv()? {
            Response::Status { locked, cert_count } => {
                Ok(DaemonStatus { locked, cert_count })
            }
            Response::Error { message } => bail!("Daemon error: {}", message),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Lock the store.
    pub fn lock(&mut self) -> Result<()> {
        self.send(&Request::Lock)?;
        match self.recv()? {
            Response::Ok => Ok(()),
            Response::Error { message } => bail!("Daemon error: {}", message),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// List all certificates.
    pub fn list_certs(&mut self) -> Result<Vec<CertSummary>> {
        self.send(&Request::ListCerts)?;
        match self.recv()? {
            Response::Certs { certs } => Ok(certs),
            Response::Error { message } => bail!("Daemon error: {}", message),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Wire format — matches coned's IPC framing exactly
    // -----------------------------------------------------------------------

    fn send(&mut self, request: &Request) -> Result<()> {
        let json = serde_json::to_vec(request)?;
        let len  = (json.len() as u32).to_be_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(&json)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Response> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf)?;

        serde_json::from_slice(&buf)
            .context("Failed to parse daemon response")
    }
}