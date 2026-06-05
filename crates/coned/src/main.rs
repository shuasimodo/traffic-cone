//! coned — the Traffic Cone daemon.
//!
//! Startup sequence (strict order):
//!
//! 1. Check process environment — refuse if LD_PRELOAD / LD_AUDIT set
//! 2. Verify binary integrity (manifest + database)
//! 3. prctl(PR_SET_DUMPABLE, 0) — disable ptrace / core dumps
//! 4. Start IPC server (abstract Unix socket)
//! 5. Start SSH agent server
//! 6. Accept connections — verify each via SO_PEERCRED + binary hash

mod hardening;
mod ipc;
mod routing;
mod process_monitor;
mod ssh_agent;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    tracing::info!("Traffic Cone daemon starting");

    // Step 1: environment check
    hardening::check_environment()?;

    // Step 2: integrity verification
    // (requires passphrase — prompted on first unlock, then store checked)

    // Step 3: harden the process
    hardening::harden_process()?;

    tracing::info!("Process hardened — ptrace disabled");

    // Step 4 & 5: start servers
    // TODO: implement IPC and SSH agent servers

    tracing::info!("coned ready");

    // Keep running until signalled
    tokio::signal::ctrl_c().await?;
    tracing::info!("coned shutting down");

    Ok(())
}
