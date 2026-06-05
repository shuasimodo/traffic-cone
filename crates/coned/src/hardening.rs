//! Process hardening applied at daemon startup.

use anyhow::{bail, Result};

/// Check for dangerous environment variables that could allow
/// shared library injection into this process.
pub fn check_environment() -> Result<()> {
    let dangerous = ["LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "DYLD_INSERT_LIBRARIES"];

    for var in &dangerous {
        if std::env::var(var).is_ok() {
            bail!(
                "Refusing to start: {} is set in the environment. \
                 Traffic Cone will not run with dynamic linker overrides active.",
                var
            );
        }
    }

    Ok(())
}

/// Apply OS-level hardening to the current process.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<()> {
    use nix::sys::prctl;

    // Disable ptrace attachment and core dumps.
    // After this call, no process (including root processes that dropped
    // privileges) can attach a debugger to coned or trigger a core dump.
    prctl::set_dumpable(false)
        .map_err(|e| anyhow::anyhow!("prctl(PR_SET_DUMPABLE) failed: {}", e))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<()> {
    // No-op on non-Linux platforms during development
    Ok(())
}
