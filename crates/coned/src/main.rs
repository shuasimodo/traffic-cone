//! coned — Traffic Cone daemon.
//!
//! Startup sequence (strict order — do not reorder):
//!
//! 1. Check environment (LD_PRELOAD etc.)
//! 2. Check not running as root
//! 3. Harden process (prctl, ptrace disabled)
//! 4. Open store and prompt for master passphrase
//! 5. Verify binary integrity (manifest + database)
//! 6. Load known binary hashes for IPC verification
//! 7. Start IPC server and SSH agent server

mod hardening;
mod ipc;
mod process_monitor;
mod routing;
mod ssh_agent;

use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use cone_store::Store;

use process_monitor::ProcessMonitor;

fn main() -> Result<()> {
    // Initialise logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("Traffic Cone {} starting", env!("CARGO_PKG_VERSION"));

    // -----------------------------------------------------------------------
    // Step 1: Environment check
    // Must happen before anything else.
    // -----------------------------------------------------------------------
    hardening::check_environment()
        .context("Environment check failed")?;

    // -----------------------------------------------------------------------
    // Step 2: Refuse to run as root
    // -----------------------------------------------------------------------
    hardening::check_not_root()
        .context("Root check failed")?;

    // -----------------------------------------------------------------------
    // Step 3: Harden the process
    // Disable ptrace and core dumps before opening the store.
    // -----------------------------------------------------------------------
    hardening::harden_process()
        .context("Process hardening failed")?;

    tracing::info!("Process hardened");

    // -----------------------------------------------------------------------
    // Step 4: Open the store and unlock with master passphrase
    // -----------------------------------------------------------------------
    let store_path = get_store_path()?;
    tracing::info!("Store path: {}", store_path);

    let mut store = Store::open(&store_path);

    // Prompt for master passphrase
    let passphrase = prompt_passphrase("Traffic Cone master passphrase: ")?;

    store.unlock(passphrase.as_bytes())
        .context("Failed to unlock store — wrong passphrase?")?;

    tracing::info!("Store unlocked");

    // -----------------------------------------------------------------------
    // Step 5: Verify binary integrity
    // Both the signed manifest and the database record must pass.
    // -----------------------------------------------------------------------
    match cone_store::integrity::verify_all(&store) {
        Ok(()) => {
            tracing::info!("Integrity check passed");
        }
        Err(e) => {
            // Clear the passphrase from memory before exiting
            drop(passphrase);

            tracing::error!(
                "INTEGRITY CHECK FAILED: {}\n\
                 One or more Traffic Cone binaries have been modified since installation.\n\
                 Your keys have not been accessed. Please reinstall from a verified source.",
                e
            );

            // Write to stderr as well so the user sees it even without logging
            eprintln!(
                "\nTraffic Cone integrity check failed: {}\n\
                 Your keys have not been accessed.\n\
                 Please reinstall Traffic Cone from a verified source.\n",
                e
            );

            std::process::exit(1);
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: Load known binary hashes for IPC verification
    // -----------------------------------------------------------------------
    let known_hashes = routing::load_known_hashes(&store)
        .context("Failed to load integrity records from store")?;

    tracing::info!(
        "Loaded {} known binary hashes for IPC verification",
        known_hashes.len()
    );

    // -----------------------------------------------------------------------
    // Step 7: Start servers
    // -----------------------------------------------------------------------
    let store   = Arc::new(Mutex::new(store));
    let monitor = Arc::new(ProcessMonitor::new());

    tracing::info!("Starting IPC server and SSH agent");

    // IPC server — handles cone CLI and libcone.so connections
    let ipc_server = ipc::IpcServer::new(
        Arc::clone(&store),
        Arc::clone(&monitor),
        known_hashes,
    );

    // SSH agent server — handles SSH client connections
    let ssh_server = ssh_agent::SshAgentServer::new(
        Arc::clone(&store),
        Arc::clone(&monitor),
    );

    // Run both servers on separate threads
    let ipc_thread = thread::spawn(move || {
        if let Err(e) = ipc_server.run() {
            tracing::error!("IPC server error: {}", e);
        }
    });

    let ssh_thread = thread::spawn(move || {
        if let Err(e) = ssh_server.run() {
            tracing::error!("SSH agent error: {}", e);
        }
    });

    tracing::info!("coned ready");

    // Wait for both servers — they run until the process is killed
    ipc_thread.join().ok();
    ssh_thread.join().ok();

    tracing::info!("coned shutting down");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine the store path from XDG_DATA_HOME or default.
fn get_store_path() -> Result<String> {
    let data_home = std::env::var("XDG_DATA_HOME")
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.local/share", home)
        });

    let dir = format!("{}/cone", data_home);
    std::fs::create_dir_all(&dir)
        .context("Failed to create store directory")?;

    Ok(format!("{}/store.db", dir))
}

/// Prompt for a passphrase without echoing to the terminal.
fn prompt_passphrase(prompt: &str) -> Result<String> {
    // In a real deployment this uses the terminal directly.
    // When running as a systemd user service, the passphrase
    // is provided via a secrets mechanism or prompted at login.
    //
    // For now: check environment variable for non-interactive use
    // (useful for development and testing — not for production).
    if let Ok(pass) = std::env::var("CONE_PASSPHRASE") {
        tracing::warn!(
            "Using passphrase from CONE_PASSPHRASE environment variable. \
             This is for development only."
        );
        return Ok(pass);
    }

    // Interactive prompt — reads from /dev/tty directly so it works
    // even when stdin is redirected
    eprint!("{}", prompt);
    let passphrase = rpassword::read_password()
        .context("Failed to read passphrase")?;

    Ok(passphrase)
}