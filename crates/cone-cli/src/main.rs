//! cone — Traffic Cone CLI management tool.
//!
//! Commands that need the store unlocked talk to coned over IPC.
//! Commands that work offline (backup, restore, import when daemon
//! is not running) access the store directly.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{Password, Input};

mod client;

use client::IpcClient;

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
    /// Show store and daemon status
    Status,
    /// Lock the store
    Lock,
    /// Import a client certificate
    Import {
        #[arg(long, help = "PFX, P12, or PEM file")]
        file: Option<String>,
        #[arg(long, help = "Certificate file (when using separate cert + key)")]
        cert: Option<String>,
        #[arg(long, help = "Private key file (when using separate cert + key)")]
        key: Option<String>,
        #[arg(long, help = "Label for this certificate")]
        label: String,
    },
    /// List all client certificates
    List,
    /// Remove a certificate
    Remove {
        #[arg(long)]
        label: String,
    },
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
    /// Test which certificate would be presented for a host
    Test {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        ip: Option<String>,
    },
    /// Show recent audit log entries
    Audit {
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Run integrity verification manually
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
    /// Update hash after an application update
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
        #[arg(long, default_value = "0")]
        priority: i64,
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
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let mut client = IpcClient::connect()?;
            let status = client.status()?;
            if status.locked {
                println!("● coned running");
                println!("  Store: locked");
            } else {
                println!("● coned running");
                println!("  Store: unlocked · {} certs", status.cert_count);
            }
        }

        Commands::Lock => {
            let mut client = IpcClient::connect()?;
            client.lock()?;
            println!("Store locked.");
        }

        Commands::List => {
            let mut client = IpcClient::connect()?;
            let certs = client.list_certs()?;
            if certs.is_empty() {
                println!("No certificates stored.");
                println!("Import one with: cone import --file laptop.pfx --label \"My Cert\"");
            } else {
                println!("{:<36}  {:<20}  {}", "ID", "LABEL", "SUBJECT");
                println!("{}", "-".repeat(80));
                for cert in &certs {
                    println!(
                        "{:<36}  {:<20}  {}",
                        &cert.id[..8],
                        cert.label,
                        cert.subject,
                    );
                }
            }
        }

        Commands::Import { file, cert, key, label } => {
            let store = open_store_direct()?;

            let passphrase = if let Some(ref f) = file {
                if f.ends_with(".pfx") || f.ends_with(".p12") {
                    Password::new()
                        .with_prompt("PFX passphrase")
                        .allow_empty_password(true)
                        .interact()?
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let result = match (file, cert, key) {
                (Some(f), _, _) => {
                    cone_store::import::import_file(
                        &store, &f, &passphrase, &label, None
                    )?
                }
                (None, Some(c), Some(k)) => {
                    cone_store::import::import_file(
                        &store, &c, &passphrase, &label, Some(&k)
                    )?
                }
                _ => {
                    anyhow::bail!(
                        "Provide either --file for PFX/PEM, or both --cert and --key"
                    );
                }
            };

            println!("{}", result.summary);

            if !result.ca_chain.is_empty() {
                println!(
                    "\n{} CA certificate(s) found in this file.",
                    result.ca_chain.len()
                );
                println!(
                    "Import them with: cone ca add --file <ca.pem> --label \"CA Name\""
                );
            }
        }

        Commands::Remove { label } => {
            let store = open_store_direct()?;
            cone_store::list::delete_cert(&store, &label)?;
            println!("Removed certificate '{}'.", label);
        }

        Commands::Backup { out } => {
            let store = open_store_direct()?;
            let backup_pass = Password::new()
                .with_prompt("Backup passphrase")
                .with_confirmation("Confirm backup passphrase", "Passphrases do not match")
                .interact()?;

            let data = cone_store::export::create_backup(&store, &backup_pass)?;
            std::fs::write(&out, &data)
                .with_context(|| format!("Failed to write backup to {}", out))?;

            println!("Backup written to {}", out);
            println!("Keep this file and your backup passphrase somewhere safe.");
            println!("Your master passphrase is also required to restore key material.");
        }

        Commands::Restore { file } => {
            let store = open_store_direct()?;
            let backup_data = std::fs::read(&file)
                .with_context(|| format!("Failed to read backup file {}", file))?;

            let backup_pass = Password::new()
                .with_prompt("Backup passphrase")
                .interact()?;

            let result = cone_store::export::restore_backup(
                &store, &backup_data, &backup_pass
            )?;

            println!("Restored successfully:");
            println!("  {} client certificates", result.certs);
            println!("  {} SSH keys",           result.ssh_keys);
            println!("  {} CA certificates",    result.ca_certs);
            println!("  {} applications",       result.apps);
            println!("  {} routes",             result.routes + result.ssh_routes);
        }

        Commands::Audit { limit } => {
            let store = open_store_direct()?;
            let entries = cone_store::list::list_audit_log(&store, limit)?;
            if entries.is_empty() {
                println!("No audit log entries.");
            } else {
                for entry in &entries {
                    let ts = format_timestamp(entry.occurred_at);
                    let detail = entry.detail.as_deref().unwrap_or("");
                    println!("[{}] {} {}", ts, entry.event_type, detail);
                }
            }
        }

        Commands::Verify => {
            let store = open_store_direct()?;
            print!("Verifying integrity... ");
            match cone_store::integrity::verify_all(&store) {
                Ok(()) => println!("✓ All binaries verified."),
                Err(e) => {
                    println!("FAILED");
                    eprintln!("Integrity check failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Ca { command } => match command {
            CaCommands::List => {
                let store = open_store_direct()?;
                let certs = cone_store::list::list_ca_certs(&store)?;
                if certs.is_empty() {
                    println!("No CA certificates stored.");
                } else {
                    for cert in &certs {
                        println!("{} — {}", cert.label, cert.subject);
                    }
                }
            }
            CaCommands::Add { file, label } => {
                println!("CA import: {} as '{}'", file, label);
                println!("TODO: implement CA trust store write");
            }
            CaCommands::Remove { label } => {
                println!("TODO: remove CA '{}'", label);
            }
        }

        Commands::Ssh { command } => match command {
            SshCommands::List => {
                let store = open_store_direct()?;
                let keys = cone_store::list::list_ssh_keys(&store)?;
                if keys.is_empty() {
                    println!("No SSH keys stored.");
                } else {
                    for key in &keys {
                        println!("{} — {}", key.label, key.public_key);
                    }
                }
            }
            SshCommands::Import { file, label } => {
                println!("TODO: import SSH key {} as '{}'", file, label);
            }
            SshCommands::Remove { label } => {
                println!("TODO: remove SSH key '{}'", label);
            }
            SshCommands::Route { command } => match command {
                SshRouteCommands::List => {
                    let store = open_store_direct()?;
                    let routes = cone_store::list::list_ssh_routes(&store)?;
                    println!("{} SSH routes", routes.len());
                }
                SshRouteCommands::Add { key, app, host } => {
                    println!("TODO: add SSH route key={} app={:?} host={:?}", key, app, host);
                }
                SshRouteCommands::Remove { id } => {
                    println!("TODO: remove SSH route {}", id);
                }
            }
        }

        Commands::App { command } => match command {
            AppCommands::List => {
                let store = open_store_direct()?;
                let apps = cone_store::list::list_apps(&store)?;
                if apps.is_empty() {
                    println!("No applications registered.");
                } else {
                    println!("{:<20}  {}", "LABEL", "PATH");
                    println!("{}", "-".repeat(60));
                    for app in &apps {
                        println!("{:<20}  {}", app.label, app.exe_path);
                    }
                }
            }
            AppCommands::Add { label, exe } => {
                let store = open_store_direct()?;
                let hash = cone_store::integrity::hash_file_path(&exe)?;
                let now = unix_now();
                let id  = new_id();
                store.execute(
                    "INSERT INTO apps (id, label, exe_path, exe_hash, registered_at)
                    VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![id, label, exe, hash, now],
                ).context("Failed to register application")?;
                println!("Registered '{}' at {}", label, exe);
                println!("Hash: {}", &hash[..16]);
            }
            AppCommands::Verify { label } => {
                let store = open_store_direct()?;
                let apps  = cone_store::list::list_apps(&store)?;
                let app   = apps.iter()
                    .find(|a| a.label == label)
                    .ok_or_else(|| anyhow::anyhow!("App '{}' not found", label))?;

                let current = cone_store::integrity::hash_file_path(&app.exe_path)?;
                if current == app.exe_hash {
                    println!("✓ '{}' binary matches registered hash", label);
                } else {
                    eprintln!("✗ Hash mismatch for '{}'!", label);
                    eprintln!("  Expected: {}", app.exe_hash);
                    eprintln!("  Found:    {}", current);
                    std::process::exit(1);
                }
            }
            AppCommands::Update { label } => {
                println!("TODO: update hash for '{}'", label);
            }
            AppCommands::Remove { label } => {
                println!("TODO: remove app '{}'", label);
            }
        }

        Commands::Route { command } => match command {
            RouteCommands::List => {
                let store  = open_store_direct()?;
                let routes = cone_store::list::list_routes(&store)?;
                if routes.is_empty() {
                    println!("No routes configured.");
                } else {
                    for r in &routes {
                        println!(
                            "[{}] cert={} app={} pattern={} require_both={}",
                            r.id,
                            &r.cert_id[..8],
                            r.app_id.as_deref().unwrap_or("any"),
                            r.pattern.as_deref().unwrap_or("any"),
                            r.require_both,
                        );
                    }
                }
            }
            RouteCommands::Add { cert, app, host, ip, require_both, priority } => {
                let store    = open_store_direct()?;
                let cert_row = cone_store::list::get_cert_by_label(&store, &cert)
                    .map_err(|_| anyhow::anyhow!("Certificate '{}' not found", cert))?;

                let app_id = if let Some(ref app_label) = app {
                    let apps = cone_store::list::list_apps(&store)?;
                    Some(
                        apps.iter()
                            .find(|a| &a.label == app_label)
                            .ok_or_else(|| anyhow::anyhow!(
                                "App '{}' not found — register it first with: \
                                 cone app add --label \"{}\" --exe /path/to/binary",
                                app_label, app_label
                            ))?
                            .id
                            .clone()
                    )
                } else {
                    None
                };

                let (match_type, pattern) = match (host, ip) {
                    (Some(h), _) => ("hostname", Some(h)),
                    (_, Some(i)) => ("ip", Some(i)),
                    _ => ("hostname", None),
                };

                let id  = new_id();
                let now = unix_now();

                store.execute(
                    "INSERT INTO routes \
                     (id, cert_id, app_id, match_type, pattern, require_both, priority, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        id,
                        cert_row.id,
                        app_id,
                        match_type,
                        pattern,
                        require_both as i64,
                        priority,
                        now,
                    ],
                ).context("Failed to add route")?;

                println!("Route added (id: {})", &id[..8]);
            }
            RouteCommands::Remove { id } => {
                let store = open_store_direct()?;
                store.execute(
                    "DELETE FROM routes WHERE id = ?1 OR id LIKE ?2",
                    rusqlite::params![id, format!("{}%", id)],
                )?;
                println!("Route removed.");
            }
        }

        Commands::Test { host, ip } => {
            let store  = open_store_direct()?;
            let result = cone_store::list::resolve_route(
                &store,
                None,
                host.as_deref(),
                ip.as_deref(),
            )?;
            match result {
                Some(cert_id) => {
                    let cert = cone_store::list::get_cert_by_id(&store, &cert_id)?;
                    println!("✓ Would present: {} ({})", cert.label, cert.subject);
                }
                None => {
                    println!("✗ No route matched — no certificate would be presented.");
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

/// Open the store directly (offline operations).
fn open_store_direct() -> Result<cone_store::Store> {
    let store_path = get_store_path()?;
    let mut store  = cone_store::Store::open(&store_path);

    let passphrase = if let Ok(p) = std::env::var("CONE_PASSPHRASE") {
        p
    } else {
        Password::new()
            .with_prompt("Master passphrase")
            .interact()?
    };

    store.unlock(passphrase.as_bytes())
        .context("Failed to unlock store — wrong passphrase?")?;

    Ok(store)
}

fn get_store_path() -> Result<String> {
    let data_home = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.local/share", home)
    });
    let dir = format!("{}/cone", data_home);
    std::fs::create_dir_all(&dir).context("Failed to create store directory")?;
    Ok(format!("{}/store.db", dir))
}

fn format_timestamp(ts: i64) -> String {
    // Simple ISO-ish format without pulling in chrono
    let secs = ts as u64;
    let mins  = secs / 60;
    let hours = mins / 60;
    let days  = hours / 24;
    format!("{}d {:02}:{:02}", days, hours % 24, mins % 60)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn new_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}