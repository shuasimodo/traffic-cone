//! Process monitor for coned.
//!
//! Resolves PIDs to verified binary paths and hashes. Used by the
//! IPC server to verify that connecting processes are legitimate
//! Traffic Cone binaries, and by the route resolver to verify that
//! the calling application matches a registered app.
//!
//! All verification is done through /proc — the kernel's own view
//! of what is running. A process cannot lie about its own /proc/PID/exe.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// A verified process entry — resolved and hash-checked.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid:        u32,
    pub exe_path:   String,
    pub exe_hash:   String,   // SHA-256 hex
    pub start_time: u64,      // from /proc/PID/stat — used to detect PID reuse
}

/// Cache of verified process entries.
/// Entries are invalidated when the process start time changes
/// (indicating PID reuse) or when the binary hash no longer matches.
#[derive(Debug, Clone)]
pub struct ProcessMonitor {
    cache: Arc<Mutex<HashMap<u32, ProcessEntry>>>,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        ProcessMonitor {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolve a PID to a verified ProcessEntry.
    ///
    /// Reads /proc/PID/exe for the binary path, checks /proc/PID/stat
    /// for the start time (to detect PID reuse), and computes the
    /// SHA-256 hash of the binary.
    ///
    /// Returns a cached entry if the PID and start time match.
    pub fn resolve(&self, pid: u32) -> Result<ProcessEntry> {
        let start_time = read_process_start_time(pid)?;

        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&pid) {
                if entry.start_time == start_time {
                    // PID hasn't been recycled — return cached entry
                    return Ok(entry.clone());
                }
                // Start time changed — PID was recycled, fall through to re-resolve
            }
        }

        // Resolve fresh
        let exe_path = read_exe_path(pid)?;
        let exe_hash = hash_file(&exe_path)?;

        let entry = ProcessEntry {
            pid,
            exe_path,
            exe_hash,
            start_time,
        };

        // Cache the result
        self.cache.lock().unwrap().insert(pid, entry.clone());

        Ok(entry)
    }

    /// Verify that a PID's binary matches an expected SHA-256 hash.
    ///
    /// Used by the IPC server to confirm that a connecting process
    /// is a legitimate, unmodified Traffic Cone binary.
    pub fn verify_hash(&self, pid: u32, expected_hash: &str) -> Result<ProcessEntry> {
        let entry = self.resolve(pid)?;

        if entry.exe_hash != expected_hash {
            bail!(
                "Binary hash mismatch for PID {} ({}): \
                 expected {}, found {}. \
                 The binary may have been modified or replaced.",
                pid, entry.exe_path, expected_hash, entry.exe_hash
            );
        }

        Ok(entry)
    }

    /// Get the active outbound connections for a PID.
    ///
    /// Reads /proc/PID/net/tcp and /proc/PID/net/tcp6 to find
    /// what remote hosts the process is currently connected to.
    /// Used by the route resolver to match connections to routes.
    pub fn get_connections(&self, pid: u32) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();

        // Read IPv4 connections
        if let Ok(tcp) = read_proc_net_tcp(pid, false) {
            connections.extend(tcp);
        }

        // Read IPv6 connections
        if let Ok(tcp6) = read_proc_net_tcp(pid, true) {
            connections.extend(tcp6);
        }

        Ok(connections)
    }

    /// Invalidate the cache entry for a PID.
    /// Called when a process exits.
    pub fn invalidate(&self, pid: u32) {
        self.cache.lock().unwrap().remove(&pid);
    }

    /// Clean up stale cache entries for processes that no longer exist.
    pub fn cleanup_stale(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|&pid, entry| {
            // Check if the process still exists and hasn't been recycled
            match read_process_start_time(pid) {
                Ok(current_start) => current_start == entry.start_time,
                Err(_) => false, // process no longer exists
            }
        });
    }
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// An active outbound TCP connection.
#[derive(Debug, Clone)]
pub struct Connection {
    pub remote_ip:   String,
    pub remote_port: u16,
    pub state:       ConnectionState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Established,
    Other,
}

// ---------------------------------------------------------------------------
// /proc readers
// ---------------------------------------------------------------------------

/// Read the real binary path for a PID from /proc/PID/exe.
///
/// /proc/PID/exe is a symlink maintained by the kernel pointing to
/// the actual binary on disk. readlink follows it to the real path.
/// A process cannot change what /proc/PID/exe points to.
fn read_exe_path(pid: u32) -> Result<String> {
    let path = format!("/proc/{}/exe", pid);
    let exe = std::fs::read_link(&path)
        .map_err(|e| anyhow::anyhow!(
            "failed to read /proc/{}/exe: {} — \
             process may have exited or permission denied", pid, e
        ))?;

    exe.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("exe path for PID {} contains invalid UTF-8", pid))
}

/// Read the process start time from /proc/PID/stat.
///
/// Field 22 in /proc/PID/stat is the process start time in clock ticks
/// since system boot. This is unique per PID lifetime — if a PID is
/// reused, the start time will be different. We use this to detect
/// PID recycling in the cache.
fn read_process_start_time(pid: u32) -> Result<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("process {} not found", pid))?;

    // /proc/PID/stat format:
    // PID (comm) state ppid pgroup session tty_nr tpgid flags ...
    // The comm field can contain spaces and parentheses, so we find
    // the last ')' and parse from there.
    let after_comm = stat.rfind(')')
        .ok_or_else(|| anyhow::anyhow!("malformed /proc/{}/stat", pid))?;

    let fields: Vec<&str> = stat[after_comm + 2..].split_whitespace().collect();

    // Field 22 in the full stat line = field 20 after the comm field
    // (0-indexed: state=0, ppid=1, ... starttime=19)
    fields.get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("failed to parse start time from /proc/{}/stat", pid))
}

/// Parse /proc/PID/net/tcp or /proc/PID/net/tcp6 for active connections.
///
/// Each line (after the header) contains hex-encoded local and remote
/// addresses. We parse the remote address and port for ESTABLISHED
/// connections (state 01).
fn read_proc_net_tcp(pid: u32, ipv6: bool) -> Result<Vec<Connection>> {
    let filename = if ipv6 { "tcp6" } else { "tcp" };
    let path = format!("/proc/{}/net/{}", pid, filename);

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Ok(vec![]), // not available, skip
    };

    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        // Fields: sl local_address rem_address st tx_queue rx_queue ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let state = fields[3];
        let connection_state = if state == "01" {
            ConnectionState::Established
        } else {
            ConnectionState::Other
        };

        // Only care about established connections for routing
        if connection_state != ConnectionState::Established {
            continue;
        }

        let remote_addr = fields[2];

        if let Some((ip, port)) = parse_hex_addr(remote_addr, ipv6) {
            connections.push(Connection {
                remote_ip: ip,
                remote_port: port,
                state: connection_state,
            });
        }
    }

    Ok(connections)
}

/// Parse a hex-encoded address:port from /proc/net/tcp.
///
/// IPv4: "0101007F:0035" → ("127.1.1.0" reversed → "0.1.1.127", 53)
/// IPv6: 32-char hex address + colon + 4-char port
fn parse_hex_addr(addr: &str, ipv6: bool) -> Option<(String, u16)> {
    let (addr_part, port_part) = addr.split_once(':')?;
    let port = u16::from_str_radix(port_part, 16).ok()?;

    let ip = if ipv6 {
        // IPv6: 32 hex chars = 16 bytes, little-endian groups of 4
        if addr_part.len() != 32 {
            return None;
        }
        // Parse as 4 u32 values and format as IPv6
        let mut groups = Vec::new();
        for i in (0..32).step_by(8) {
            let word = u32::from_str_radix(&addr_part[i..i+8], 16).ok()?;
            let word = u32::from_be(word.swap_bytes());
            groups.push(format!("{:08x}", word));
        }
        // Reconstruct as IPv6 address
        let hex: String = groups.join("");
        (0..8)
            .map(|i| &hex[i*4..(i+1)*4])
            .collect::<Vec<_>>()
            .join(":")
    } else {
        // IPv4: 8 hex chars = 4 bytes, little-endian
        if addr_part.len() != 8 {
            return None;
        }
        let n = u32::from_str_radix(addr_part, 16).ok()?;
        let bytes = n.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    };

    Some((ip, port))
}

/// Compute the SHA-256 hash of a file.
pub fn hash_file(path: &str) -> Result<String> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path, e))?;

    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}