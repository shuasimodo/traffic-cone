//! Process hardening for coned.
//!
//! Applied at daemon startup before any connections are accepted
//! or any key material is accessed. These calls are irreversible
//! for the lifetime of the process — that is intentional.
//!
//! Order matters: environment check must happen first, before
//! anything else runs. prctl hardening happens after integrity
//! verification passes.

use anyhow::{bail, Result};

/// Step 1 — Check for dangerous environment variables.
///
/// Dynamic linker overrides like LD_PRELOAD allow arbitrary code
/// to be injected into this process before main() runs. We check
/// for them at startup and refuse to run if any are set.
///
/// This runs before anything else — before the store is opened,
/// before integrity is checked, before any connections are accepted.
pub fn check_environment() -> Result<()> {
    let dangerous = [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "DYLD_INSERT_LIBRARIES", // macOS equivalent
    ];

    for var in &dangerous {
        if std::env::var(var).is_ok() {
            bail!(
                "Traffic Cone refuses to start: {} is set in the environment.\n\
                 Dynamic linker overrides allow code injection and cannot be \
                 permitted in a process that handles private key material.\n\
                 Unset {} and try again.",
                var, var
            );
        }
    }

    Ok(())
}

/// Step 2 — Harden the process after integrity verification passes.
///
/// These calls lock down the running process so that even a
/// privileged attacker cannot inspect its memory or attach a debugger.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    use nix::sys::prctl;

    // Disable ptrace attachment and core dumps.
    //
    // After this call:
    // - No process can attach gdb/strace to coned
    // - No process can send SIGABRT to trigger a core dump
    // - /proc/coned_PID/mem is not readable by other processes
    //
    // This applies even to root-owned processes that dropped back
    // to user level (e.g. a malicious setuid binary).
    prctl::set_dumpable(false)
        .map_err(|e| anyhow::anyhow!(
            "prctl(PR_SET_DUMPABLE, 0) failed: {} — \
             coned cannot run without this protection", e
        ))?;

    tracing::debug!("Process hardened: ptrace disabled, core dumps disabled");

    Ok(())
}

/// Lock memory pages containing sensitive data to prevent swapping.
///
/// Called after key material is loaded into memory. Prevents the OS
/// from writing key bytes to the swap partition where they could be
/// recovered from disk after shutdown.
///
/// # Safety
/// mlock is safe to call — it only affects which pages get swapped,
/// not memory safety in the Rust sense.
#[cfg(target_os = "linux")]
pub fn lock_memory_pages(ptr: *const u8, len: usize) -> Result<()> {
    use nix::sys::mman;

    // SAFETY: ptr and len describe a valid allocation passed in by the caller
    unsafe {
        let nn = std::ptr::NonNull::new(ptr as *mut std::ffi::c_void)
            .ok_or_else(|| anyhow::anyhow!("mlock called with null pointer"))?;
        mman::mlock(nn, len)
            .map_err(|e| anyhow::anyhow!("mlock failed: {}", e))?;
    }

    Ok(())
}

/// Verify that the process is running as a normal user, not root.
///
/// coned should never run as root. If it does, something is wrong
/// with the installation and we should refuse to start rather than
/// risk operating with elevated privileges.
pub fn check_not_root() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let uid = nix::unistd::getuid();
        if uid.is_root() {
            bail!(
                "Traffic Cone refuses to start as root.\n\
                 coned is a user service and must run as a normal user.\n\
                 Check your systemd service configuration."
            );
        }
    }

    Ok(())
}

/// Non-Linux stub — hardening is a no-op on non-Linux platforms.
/// Useful for development on macOS.
#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<()> {
    tracing::warn!(
        "Process hardening is not implemented on this platform. \
         coned should only be deployed on Linux."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn lock_memory_pages(_ptr: *const u8, _len: usize) -> Result<()> {
    Ok(())
}