//! cone — Traffic Cone CLI management tool.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cone",
    about = "Traffic Cone — credential manager",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Unlock the credential store
    Unlock,
    /// Lock the credential store
    Lock,
    /// Show store status and integration health
    Status,
    /// Show recent audit log entries
    Audit,
    /// Import a client certificate
    Import {
        /// PFX, P12, or PEM file
        #[arg(long)]
        file: Option<String>,
        /// Certificate file (when providing cert and key separately)
        #[arg(long)]
        cert: Option<String>,
        /// Private key file (when providing cert and key separately)
        #[arg(long)]
        key: Option<String>,
    },
    /// List all client certificates
    List,
    /// CA trust store management
    Ca {
        #[command(subcommand)]
        command: CaCommands,
    },
    /// SSH key management
    Ssh {
        #[command(subcommand)]
        command: SshCommands,
    },
    /// Application registration
    App {
        #[command(subcommand)]
        command: AppCommands,
    },
    /// Routing rule management
    Route {
        #[command(subcommand)]
        command: RouteCommands,
    },
    /// Create an encrypted backup
    Backup {
        #[arg(long)]
        out: String,
    },
    /// Restore from a backup
    Restore {
        #[arg(long)]
        file: String,
    },
    /// Test which certificate would be presented for a given host
    Test {
        #[arg(long)]
        host: String,
    },
    /// Manually run integrity verification
    Verify,
}

#[derive(Subcommand)]
enum CaCommands {
    /// Import a CA certificate into the system trust store
    Add {
        #[arg(long)]
        file: String,
        #[arg(long)]
        label: String,
    },
    /// List CA certificates
    List,
    /// Remove a CA certificate
    Remove {
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
enum SshCommands {
    /// Import an SSH key
    Import {
        #[arg(long)]
        file: String,
        #[arg(long)]
        label: String,
    },
    /// List SSH keys
    List,
    /// Remove an SSH key
    Remove {
        #[arg(long)]
        label: String,
    },
    /// SSH route management
    Route {
        #[command(subcommand)]
        command: SshRouteCommands,
    },
}

#[derive(Subcommand)]
enum SshRouteCommands {
    Add {
        #[arg(long)]
        key: String,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        host: Option<String>,
    },
    List,
    Remove {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
enum AppCommands {
    /// Register an application
    Add {
        #[arg(long)]
        label: String,
        #[arg(long)]
        exe: String,
    },
    /// List registered applications
    List,
    /// Verify a registered application's binary hash
    Verify {
        #[arg(long)]
        label: String,
    },
    /// Update a registered application's hash after an app update
    Update {
        #[arg(long)]
        label: String,
    },
    /// Remove a registered application
    Remove {
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
enum RouteCommands {
    /// Add a routing rule
    Add {
        #[arg(long)]
        cert: String,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        require_both: bool,
    },
    /// List all routing rules
    List,
    /// Remove a routing rule
    Remove {
        #[arg(long)]
        id: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("Traffic Cone");
            println!("TODO: connect to coned and report status");
        }
        Commands::Verify => {
            println!("Running integrity verification...");
            println!("TODO: verify binaries against manifest and database");
        }
        _ => {
            println!("TODO: command not yet implemented");
        }
    }

    Ok(())
}
