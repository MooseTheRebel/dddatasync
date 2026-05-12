//! Filesystem watcher — watches `~/dddatasync/` for new/changed files and
//! triggers a sync push to all enrolled peers.
//!
//! ## Lifecycle
//!
//! 1. Caller builds a [`Watcher`] via [`Watcher::new`], passing a live iroh
//!    `Endpoint`, `DddSync`, `UserIdentity`, and rendezvous base URL.
//! 2. [`Watcher::run`] blocks (async) until the provided `shutdown` future
//!    resolves (e.g. a `tokio::sync::oneshot` or `ctrl_c()`).
//! 3. On each CREATE or MODIFY event for a non-dot file inside the store root,
//!    the watcher:
//!    a. Checks store limits (`can_add`) — logs and skips if violated.
//!    b. Queries the rendezvous server for the current peer list.
//!    c. Calls `sync::push` to deliver the file to every peer.
//!
//! ## Ignored paths
//!
//! Any path whose file-name component starts with `.` is silently ignored.
//! This covers temp files (`.tmp-*`, `.dddatasync-send-*`, `.identity`, etc.)
//! and prevents the watcher from re-triggering on its own writes.
//!
//! ## Keepalive
//!
//! While running, the watcher re-registers with the rendezvous server every
//! `KEEPALIVE_INTERVAL` seconds so the TTL does not expire and other devices
//! can always find this node.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use iroh::{Endpoint, EndpointAddr};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::auth::UserIdentity;
use crate::rendezvous_client::{RegisterRequest, RendezvousClient};
use crate::store::DddSync;
use crate::sync;

/// How often (in seconds) to refresh the rendezvous registration.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Watches the store directory and pushes new/changed files to enrolled peers.
pub struct Watcher {
    endpoint: Endpoint,
    store: DddSync,
    identity: UserIdentity,
    rendezvous: RendezvousClient,
}

impl Watcher {
    /// Construct a `Watcher`.
    ///
    /// `rendezvous_url` is typically `crate::rendezvous_client::rendezvous_url()`.
    pub fn new(
        endpoint: Endpoint,
        store: DddSync,
        identity: UserIdentity,
        rendezvous_url: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            endpoint,
            store,
            identity,
            rendezvous: RendezvousClient::new(rendezvous_url, token),
        }
    }

    /// Run the watcher until `shutdown` resolves.
    ///
    /// Returns `Ok(())` when `shutdown` fires.  Any error setting up the
    /// `notify` watcher is returned immediately.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) -> anyhow::Result<()> {
        // Wait for the endpoint to be online (relay connectivity established) so
        // the address we register contains a relay URL and is actually reachable
        // by peers that cannot connect to us directly.
        info!("waiting for iroh endpoint to come online...");
        tokio::time::timeout(Duration::from_secs(30), async {
            let _ = self.endpoint.online().await;
        })
        .await
        .context("timeout waiting for iroh endpoint to come online")?;
        info!("endpoint online; setting up filesystem watcher");

        // Set up the notify watcher *before* registering with rendezvous so that
        // by the time peers can discover this node and write files, the watcher
        // is already watching the store directory.
        let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(64);

        let mut watcher = build_notify_watcher(tx)?;
        watcher
            .watch(self.store.root(), RecursiveMode::NonRecursive)
            .context("notify: watch store root")?;

        // Register with rendezvous now that we have a usable address and are
        // watching the directory.
        info!("filesystem watcher ready; registering with rendezvous");
        if let Err(e) = self.register_with_rendezvous().await {
            warn!(error = %e, "initial rendezvous registration failed; will retry on keepalive");
        }

        // Pin the shutdown future so we can select! on it.
        tokio::pin!(shutdown);

        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("watcher shutdown signal received");
                    self.rendezvous
                        .deregister(&self.identity.username, &self.identity.node_id().to_string())
                        .await;
                    return Ok(());
                }

                _ = keepalive.tick() => {
                    if let Err(e) = self.register_with_rendezvous().await {
                        warn!(error = %e, "keepalive rendezvous registration failed");
                    }
                }

                maybe_event = rx.recv() => {
                    match maybe_event {
                        None => {
                            // Channel closed — notify watcher was dropped.
                            warn!("notify channel closed unexpectedly");
                            return Ok(());
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "notify watcher error");
                        }
                        Some(Ok(event)) => {
                            self.handle_event(event).await;
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn handle_event(&self, event: Event) {
        // Only act on creates and modifications.
        if !matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_)
        ) {
            return;
        }

        for path in event.paths {
            if is_dot_file(&path) {
                continue;
            }
            if !path.is_file() {
                continue;
            }
            self.push_file(path).await;
        }
    }

    async fn push_file(&self, path: PathBuf) {
        let file_size = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "stat failed; skipping");
                return;
            }
        };

        if let Err(e) = self.store.can_add(file_size) {
            warn!(path = %path.display(), error = %e, "store limit check failed; not syncing");
            return;
        }

        let peers = match self.fetch_peers().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to fetch peers; skipping push");
                return;
            }
        };

        if peers.is_empty() {
            info!(path = %path.display(), "no peers enrolled; nothing to push");
            return;
        }

        info!(
            path = %path.display(),
            peers = peers.len(),
            "pushing file to peers"
        );

        if let Err(e) = sync::push(
            &path,
            &peers,
            self.identity.secret_key().clone(),
            self.store.root(),
        )
        .await
        {
            warn!(path = %path.display(), error = %e, "sync push failed");
        }
    }

    async fn register_with_rendezvous(&self) -> anyhow::Result<()> {
        let addr = self.endpoint.addr();
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        let addrs = addr.ip_addrs().map(|a| a.to_string()).collect();

        let req = RegisterRequest {
            username: self.identity.username.clone(),
            node_id: self.identity.node_id().to_string(),
            addrs,
            relay_url,
        };
        self.rendezvous.register(&req).await
    }

    async fn fetch_peers(&self) -> anyhow::Result<Vec<EndpointAddr>> {
        let own_id = self.identity.node_id().to_string();
        let records = self
            .rendezvous
            .fetch_peers(&self.identity.username, Some(&own_id))
            .await?;

        records
            .into_iter()
            .map(|r| {
                let node_id: iroh::PublicKey = r.node_id.parse().context("parse peer node_id")?;
                let mut addr = EndpointAddr::new(node_id);
                for s in &r.addrs {
                    let sa: std::net::SocketAddr = s.parse().context("parse peer addr")?;
                    addr = addr.with_ip_addr(sa);
                }
                if let Some(relay) = r.relay_url {
                    let url: iroh::RelayUrl = relay.parse().context("parse peer relay_url")?;
                    addr = addr.with_relay_url(url);
                }
                Ok(addr)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Internal free functions
// ---------------------------------------------------------------------------

/// Returns `true` if the path's file-name starts with `.`.
fn is_dot_file(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with('.'))
        .unwrap_or(true)
}

/// Build a `RecommendedWatcher` that sends events into `tx`.
fn build_notify_watcher(
    tx: mpsc::Sender<notify::Result<Event>>,
) -> anyhow::Result<RecommendedWatcher> {
    notify::recommended_watcher(move |res| {
        // Drop the event if the channel is full — the watcher keeps running.
        let _ = tx.blocking_send(res);
    })
    .context("create notify watcher")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_files_are_ignored() {
        assert!(is_dot_file(std::path::Path::new("/store/.tmp-abc")));
        assert!(is_dot_file(std::path::Path::new("/store/.identity")));
        assert!(is_dot_file(std::path::Path::new("/store/.dddatasync-send-01")));
        assert!(!is_dot_file(std::path::Path::new("/store/hello.txt")));
        assert!(!is_dot_file(std::path::Path::new("/store/file1")));
    }

    #[test]
    fn build_notify_watcher_succeeds() {
        let (tx, _rx) = mpsc::channel(1);
        // Just verify construction doesn't panic or error.
        build_notify_watcher(tx).expect("failed to build notify watcher");
    }
}
