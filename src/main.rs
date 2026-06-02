use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, RelayMode};
use tracing::info;

use dddatasync::auth::UserIdentity;
use dddatasync::rendezvous_client::{rendezvous_url, RendezvousClient};
use dddatasync::store::DddSync;
use dddatasync::watcher::Watcher;

#[derive(Parser)]
#[command(name = "dddatasync", about = "a CLI tool that syncs files between a user's devices automatically.")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Authenticate and enroll this device.
    Login {
        #[arg(long)]
        username: String,
        #[arg(long)]
        passphrase: String,
    },
    /// Start the background watcher daemon (blocks until Ctrl-C).
    Start,
    /// List stored files with sizes.
    List,
    /// Remove a file from the store.
    Remove {
        name: String,
    },
    /// Remove stale .tmp-* files left by a previous crash.
    Clean,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Cmd::Login { username, passphrase } => cmd_login(&username, &passphrase).await,
        Cmd::Start => cmd_start().await,
        Cmd::List => cmd_list(),
        Cmd::Remove { name } => cmd_remove(&name),
        Cmd::Clean => cmd_clean(),
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

async fn cmd_login(username: &str, passphrase: &str) -> anyhow::Result<()> {
    let identity = UserIdentity::login(username, passphrase)
        .context("login failed")?;

    // Authenticate with the rendezvous server and persist the Bearer token.
    let client = RendezvousClient::unauthenticated(rendezvous_url());
    match client.server_login(username, passphrase).await {
        Ok(token) => {
            save_token(&token).context("save rendezvous token")?;
            println!("logged in as {} (node_id: {})", identity.username, identity.node_id());
        }
        Err(e) => {
            // Warn but don't abort — the user may be logging in without a server.
            tracing::warn!(error = %e, "rendezvous server login failed; token not saved");
            println!(
                "local identity saved for {} (node_id: {}); \
                 rendezvous server login failed: {}",
                identity.username,
                identity.node_id(),
                e,
            );
        }
    }
    Ok(())
}

async fn cmd_start() -> anyhow::Result<()> {
    let identity = UserIdentity::load().context(
        "no identity found — run `dddatasync login` first",
    )?;
    let store = DddSync::open().context("open store")?;

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(identity.secret_key().clone())
        .relay_mode(RelayMode::Default)
        .alpns(vec![dddatasync::sync::SYNC_ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint")?;

    // Spawn the SyncListener to accept incoming sync offers from peers.
    let listener = dddatasync::sync::SyncListener::new(
        endpoint.clone(),
        store.root().to_path_buf(),
        identity.secret_key().clone(),
    );
    tokio::spawn(listener.run());

    let url = rendezvous_url();
    let token = load_token().unwrap_or_default();
    info!(rendezvous_url = %url, username = %identity.username, "starting watcher");

    let watcher = Watcher::new(endpoint, store, identity, url, token);

    // Shut down on Ctrl-C.
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        info!("received Ctrl-C, shutting down");
    };

    watcher.run(shutdown).await
}

fn cmd_list() -> anyhow::Result<()> {
    let store = DddSync::open().context("open store")?;
    let files = store.files().context("list files")?;

    if files.is_empty() {
        println!("store is empty");
        return Ok(());
    }

    let mut total: u64 = 0;
    for f in &files {
        println!("{:>12}  {}", human_bytes(f.size), f.name);
        total += f.size;
    }
    println!("{:>12}  (total, {} file{})", human_bytes(total), files.len(),
        if files.len() == 1 { "" } else { "s" });
    Ok(())
}

fn cmd_remove(name: &str) -> anyhow::Result<()> {
    let store = DddSync::open().context("open store")?;
    store.remove(name).context("remove file")?;
    println!("removed {}", name);
    Ok(())
}

fn cmd_clean() -> anyhow::Result<()> {
    let store = DddSync::open().context("open store")?;
    let removed = store.clean_temp_files().context("clean temp files")?;
    if removed == 0 {
        println!("no stale temp files found");
    } else {
        println!("removed {} stale .tmp-* file{}", removed, if removed == 1 { "" } else { "s" });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Token persistence
// ---------------------------------------------------------------------------

fn token_path() -> anyhow::Result<std::path::PathBuf> {
    let root = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
        .join("dddatasync");
    std::fs::create_dir_all(&root)?;
    Ok(root.join(".token"))
}

fn save_token(token: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let path = token_path()?;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn load_token() -> anyhow::Result<String> {
    let path = token_path()?;
    let token = std::fs::read_to_string(&path)
        .with_context(|| format!("read token file {:?} — run `dddatasync login` first", path))?;
    Ok(token.trim().to_owned())
}

// ---------------------------------------------------------------------------
// Formatting helper
// ---------------------------------------------------------------------------

fn human_bytes(n: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{} B", n)
    }
}
