//! Route resolution for coned.
//!
//! This is the glue between the process monitor and cone-store's
//! route table. Given a calling PID, it determines:
//!
//! 1. What binary is making the request (via process monitor)
//! 2. What host it is connecting to (via /proc/PID/net/tcp)
//! 3. Which certificate to present (via cone-store resolve_route)
//!
//! This runs on every signing request. It must be fast and it must
//! be correct — an incorrect route means either a failed connection
//! or a credential presented to the wrong destination.

use anyhow::{bail, Result};

use cone_store::list::resolve_route;
use cone_store::Store;

use crate::process_monitor::{Connection, ProcessEntry, ProcessMonitor};

/// The result of a successful route resolution.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// The certificate ID to use for this connection
    pub cert_id:   String,
    /// The process that made the request
    pub process:   ProcessEntry,
    /// The remote host that matched the route
    pub remote_host: Option<String>,
    /// The remote IP that matched the route
    pub remote_ip:   Option<String>,
}

/// Resolve which certificate to present for an incoming signing request.
///
/// # Arguments
/// * `store`   - unlocked store containing routes and certs
/// * `monitor` - process monitor for PID resolution
/// * `pid`     - PID of the process making the signing request
/// * `known_hashes` - map of exe_path → expected hash for Traffic Cone binaries
///
/// Returns the resolved route, or an error if no route matches or
/// the process fails verification.
pub fn resolve_for_pid(
    store: &Store,
    monitor: &ProcessMonitor,
    pid: u32,
    known_hashes: &std::collections::HashMap<String, String>,
) -> Result<ResolvedRoute> {
    // Step 1: resolve the PID to a verified process entry
    let process = monitor.resolve(pid)?;

    // Step 2: if this exe is a known Traffic Cone binary, verify its hash.
    // This prevents a replaced libcone.so or cone CLI from making requests.
    if let Some(expected_hash) = known_hashes.get(&process.exe_path) {
        if &process.exe_hash != expected_hash {
            bail!(
                "Binary hash mismatch for {} (PID {}): binary may have been replaced",
                process.exe_path, pid
            );
        }
    }

    // Step 3: get the active connections for this PID
    let connections = monitor.get_connections(pid)?;

    // Step 4: try to find a matching route
    // We try each established connection against the route table
    // and take the first (highest priority) match.
    for conn in &connections {
        // Try to resolve a hostname for this IP
        // For now we use the IP directly — hostname resolution is a TODO
        // that will use a reverse DNS lookup or a user-configured mapping
        let remote_ip   = Some(conn.remote_ip.as_str());
        let remote_host = None; // TODO: reverse DNS / configured hostname map

        let cert_id = resolve_route(
            store,
            Some(&process.exe_path),
            remote_host,
            remote_ip,
        )?;

        if let Some(id) = cert_id {
            return Ok(ResolvedRoute {
                cert_id:     id,
                process:     process.clone(),
                remote_host: remote_host.map(String::from),
                remote_ip:   Some(conn.remote_ip.clone()),
            });
        }
    }

    // Step 5: if no connection-specific match, try an app-only route
    // (a route with no host restriction — matches any connection from this app)
    let cert_id = resolve_route(store, Some(&process.exe_path), None, None)?;

    if let Some(id) = cert_id {
        return Ok(ResolvedRoute {
            cert_id:   id,
            process,
            remote_host: None,
            remote_ip:   None,
        });
    }

    bail!(
        "No route matched for PID {} ({}). \
         Register this application and add a route with: \
         cone app add --label \"AppName\" --exe \"{}\" && \
         cone route add --cert \"YourCert\" --app \"AppName\"",
        pid,
        process.exe_path,
        process.exe_path,
    )
}

/// Verify that a connecting PID is a legitimate Traffic Cone binary.
///
/// Used by the IPC server before accepting any requests. Only
/// libcone.so and the cone CLI are permitted to connect to coned.
///
/// Returns the verified process entry on success.
pub fn verify_traffic_cone_binary(
    monitor: &ProcessMonitor,
    pid: u32,
    uid: u32,
    expected_hashes: &std::collections::HashMap<String, String>,
) -> Result<ProcessEntry> {
    // UID must match — only our own user can connect
    let our_uid = {
        #[cfg(target_os = "linux")]
        { nix::unistd::getuid().as_raw() }
        #[cfg(not(target_os = "linux"))]
        { 1000u32 } // dev fallback
    };

    if uid != our_uid {
        bail!(
            "IPC connection rejected: UID {} does not match daemon UID {}",
            uid, our_uid
        );
    }

    // Resolve the binary path
    let process = monitor.resolve(pid)?;

    // Check that this binary is one of the known Traffic Cone binaries
    // with a matching hash
    match expected_hashes.get(&process.exe_path) {
        Some(expected) if expected == &process.exe_hash => {
            tracing::debug!(
                "Verified Traffic Cone binary: {} (PID {})",
                process.exe_path, pid
            );
            Ok(process)
        }
        Some(_) => {
            bail!(
                "IPC connection rejected: {} (PID {}) has an unexpected binary hash. \
                 The binary may have been modified.",
                process.exe_path, pid
            );
        }
        None => {
            bail!(
                "IPC connection rejected: {} (PID {}) is not a registered \
                 Traffic Cone binary.",
                process.exe_path, pid
            );
        }
    }
}

/// Build the map of known Traffic Cone binary hashes from the store.
///
/// Called at startup after integrity verification passes.
/// The returned map is used for all subsequent IPC verifications.
pub fn load_known_hashes(
    store: &Store,
) -> Result<std::collections::HashMap<String, String>> {
    use cone_store::integrity;

    let records = integrity::list(store)
        .map_err(|e| anyhow::anyhow!("failed to load integrity records: {}", e))?;

    let map = records
        .into_iter()
        .map(|r| (r.path, r.sha256))
        .collect();

    Ok(map)
}