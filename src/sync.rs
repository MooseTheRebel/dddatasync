//! iroh-blobs based file synchronisation.
//!
//! ## Model
//!
//! Sync is *pull-initiated by the sender*:
//!
//! 1. The device that has a new/changed file calls [`push`].  This function:
//!    a. Imports the file into a temporary `FsStore`.
//!    b. Starts an iroh `Router` that serves the blob.
//!    c. For every peer `EndpointAddr`, connects over our custom `SYNC_ALPN`
//!       and sends a [`SyncOffer`] message (JSON: hash + our endpoint address).
//!    d. Waits for each peer to pull the blob (signalled by `SyncAck`).
//!    e. Shuts the router down and removes the temp store.
//!
//! 2. A device that receives a `SyncOffer` (via its own `SyncListener`) calls
//!    [`pull`] internally — it connects back to the sender's iroh endpoint,
//!    downloads the blob, and writes it atomically into the local store dir.
//!
//! ## Why a custom ALPN?
//!
//! iroh-blobs is a *pull* protocol: the downloader connects to the provider.
//! We need the uploading device to *notify* each peer that new data is
//! available.  A tiny custom protocol over a second iroh connection handles
//! this without exposing tickets to the user.
//!
//! ## Temp-dir hygiene
//!
//! Each `push` call creates `.dddatasync-send-<rand>` inside the store root.
//! The dir is removed on success *and* on error; the store's `open()` method
//! warns about any leftover `.dddatasync-send-*` dirs from prior crashes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, RelayMode};
use iroh::SecretKey;
use iroh_blobs::api::blobs::{AddPathOptions, ExportMode, ExportOptions, ImportMode};
use iroh_blobs::format::collection::Collection;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobFormat, BlobsProtocol, Hash, HashAndFormat};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// ALPN for our custom sync-notification protocol
// ---------------------------------------------------------------------------

/// ALPN string identifying the dddatasync sync-offer protocol.
pub const SYNC_ALPN: &[u8] = b"dddatasync/sync/0";

// ---------------------------------------------------------------------------
// Wire messages (tiny JSON framing over raw iroh streams)
// ---------------------------------------------------------------------------

/// Sent by the *sender* to a peer over `SYNC_ALPN`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncOffer {
    /// Blake3 hash of the collection wrapping the file.
    pub hash: String,
    /// File name (no path components) so the receiver knows where to write.
    pub file_name: String,
    /// The sender's `EndpointAddr` — the peer will connect here to download.
    pub sender_addr: EndpointAddrWire,
}

/// Sent by the *receiver* back to the sender once the download is complete.
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncAck {
    pub ok: bool,
    pub error: Option<String>,
}

/// JSON-serialisable representation of an `EndpointAddr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAddrWire {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
}

impl EndpointAddrWire {
    pub fn from_endpoint_addr(addr: &EndpointAddr) -> Self {
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        let addrs = addr.ip_addrs().map(|a| a.to_string()).collect();
        Self {
            node_id: addr.id.to_string(),
            relay_url,
            addrs,
        }
    }

    pub fn to_endpoint_addr(&self) -> anyhow::Result<EndpointAddr> {
        let node_id: iroh::PublicKey = self.node_id.parse().context("parse node_id")?;
        let mut addr = EndpointAddr::new(node_id);
        for s in &self.addrs {
            let sa: std::net::SocketAddr = s.parse().context("parse direct addr")?;
            addr = addr.with_ip_addr(sa);
        }
        if let Some(ref relay) = self.relay_url {
            let url: iroh::RelayUrl = relay.parse().context("parse relay_url")?;
            addr = addr.with_relay_url(url);
        }
        Ok(addr)
    }
}

// ---------------------------------------------------------------------------
// Low-level JSON framing helpers (length-prefixed, 4-byte big-endian)
// ---------------------------------------------------------------------------

async fn write_msg<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_msg<T: for<'de> Deserialize<'de>>(
    recv: &mut iroh::endpoint::RecvStream,
) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= 64 * 1024, "sync message too large: {} bytes", len);
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Push `file_path` to each peer in `peers`.
///
/// For every peer the function connects over `SYNC_ALPN`, sends a `SyncOffer`,
/// and waits up to 2 minutes for a `SyncAck`.  Errors from individual peers
/// are logged and do not abort the push to remaining peers.
pub async fn push(
    file_path: &Path,
    peers: &[EndpointAddr],
    secret_key: SecretKey,
    store_root: &Path,
) -> anyhow::Result<()> {
    if peers.is_empty() {
        return Ok(());
    }

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("file path has no usable file name"))?
        .to_owned();

    // --- Temp store for the blob -------------------------------------------
    let tmp_dir = store_root.join(format!(".dddatasync-send-{}", nonce()));
    tokio::fs::create_dir_all(&tmp_dir).await?;
    let _cleanup = TempDirGuard(tmp_dir.clone());

    let fs_store = FsStore::load(&tmp_dir).await?;

    // --- Build the iroh router (serves blobs + our SYNC_ALPN) --------------
    let endpoint = Endpoint::empty_builder()
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
        .alpns(vec![iroh_blobs::ALPN.to_vec(), SYNC_ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint for push")?;

    let blobs = BlobsProtocol::new(&fs_store, None);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(iroh_blobs::ALPN, blobs.clone())
        .spawn();

    // Wait until we have a relay address so cross-network peers can reach us.
    tokio::time::timeout(Duration::from_secs(30), async {
        let _ = router.endpoint().online().await;
    })
    .await
    .context("timeout waiting for endpoint to go online")?;

    // --- Import the file into the blob store --------------------------------
    let collection_hash = import_file_as_collection(&fs_store, file_path).await?;
    let our_addr = EndpointAddrWire::from_endpoint_addr(&router.endpoint().addr());

    info!(
        file = %file_path.display(),
        hash = %collection_hash,
        peers = peers.len(),
        "pushing blob to peers"
    );

    let offer = SyncOffer {
        hash: collection_hash.to_string(),
        file_name,
        sender_addr: our_addr,
    };

    // --- Notify each peer ---------------------------------------------------
    let mut any_ok = false;
    for peer in peers {
        match notify_peer(router.endpoint(), peer, &offer).await {
            Ok(()) => {
                info!(peer = %peer.id, "peer acknowledged sync");
                any_ok = true;
            }
            Err(e) => {
                warn!(peer = %peer.id, error = %e, "failed to notify peer");
            }
        }
    }

    // Graceful shutdown.
    tokio::time::timeout(Duration::from_secs(5), router.shutdown())
        .await
        .ok();

    if !any_ok && !peers.is_empty() {
        warn!("push: no peers successfully acknowledged the sync offer");
    }
    Ok(())
}

/// Pull a blob from `sender_addr` and write it atomically into `dest_dir`
/// as `file_name`.
///
/// Called by [`SyncListener`] when it receives a [`SyncOffer`].
pub async fn pull(
    hash_str: &str,
    file_name: &str,
    sender_addr: EndpointAddr,
    dest_dir: &Path,
    secret_key: SecretKey,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !file_name.contains('/') && !file_name.contains('\\') && !file_name.starts_with('.'),
        "unsafe file name in sync offer: {:?}",
        file_name
    );

    let collection_hash: Hash = hash_str.parse().context("parse collection hash")?;

    let tmp_dir = dest_dir.join(format!(".dddatasync-recv-{}", nonce()));
    tokio::fs::create_dir_all(&tmp_dir).await?;
    let _cleanup = TempDirGuard(tmp_dir.clone());

    let db = FsStore::load(&tmp_dir).await.context("open recv FsStore")?;

    let endpoint = Endpoint::empty_builder()
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
        .alpns(vec![iroh_blobs::ALPN.to_vec()])
        .bind()
        .await
        .context("bind recv endpoint")?;

    // Connect to the sender's blob-serving endpoint.
    let connection = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint.connect(sender_addr, iroh_blobs::ALPN),
    )
    .await
    .context("connect timeout to sender")?
    .context("connect to sender")?;

    // Download the entire collection (HashSeq).
    db.remote()
        .fetch(connection, HashAndFormat::hash_seq(collection_hash))
        .await
        .map_err(|e| anyhow::anyhow!("fetch failed: {:?}", e))?;

    endpoint.close().await;

    // Read the collection to find the single file blob hash.
    let collection = Collection::load(collection_hash, &*db)
        .await
        .context("load collection")?;
    let (_name, file_hash) = collection
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty collection in sync offer"))?;

    // Export the file blob to a temp path then rename atomically.
    let export_tmp = dest_dir.join(format!(".dddatasync-export-{}", nonce()));
    db.export_with_opts(ExportOptions {
        hash: *file_hash,
        mode: ExportMode::Copy,
        target: export_tmp.clone(),
    })
    .await
    .map_err(|e| anyhow::anyhow!("export failed: {:?}", e))?;

    let final_path = dest_dir.join(file_name);
    tokio::fs::rename(&export_tmp, &final_path)
        .await
        .context("atomic rename of downloaded file")?;

    info!(file = %final_path.display(), "pull complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// SyncListener — drives the server side of the SYNC_ALPN protocol
// ---------------------------------------------------------------------------

/// Accepts incoming `SyncOffer` connections and calls `pull` for each.
///
/// Spawn as a background task before the watcher starts.
pub struct SyncListener {
    endpoint: Endpoint,
    dest_dir: PathBuf,
    secret_key: SecretKey,
}

impl SyncListener {
    pub fn new(endpoint: Endpoint, dest_dir: PathBuf, secret_key: SecretKey) -> Self {
        Self { endpoint, dest_dir, secret_key }
    }

    /// Accept `SyncOffer` connections until the endpoint closes.
    pub async fn run(self) {
        loop {
            let incoming = match self.endpoint.accept().await {
                Some(i) => i,
                None => break,
            };
            let dest_dir = self.dest_dir.clone();
            let secret_key = self.secret_key.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_sync_connection(incoming, dest_dir, secret_key).await {
                    warn!(error = %e, "sync connection handler failed");
                }
            });
        }
    }
}

async fn handle_sync_connection(
    incoming: iroh::endpoint::Incoming,
    dest_dir: PathBuf,
    secret_key: SecretKey,
) -> anyhow::Result<()> {
    let connection: Connection = incoming.await.context("accept incoming connection")?;

    // Only handle our ALPN; iroh-blobs handles its own via the Router.
    if connection.alpn() != SYNC_ALPN {
        return Ok(());
    }

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("accept bidirectional stream")?;

    let offer: SyncOffer = read_msg(&mut recv).await.context("read SyncOffer")?;
    let sender_addr = offer
        .sender_addr
        .to_endpoint_addr()
        .context("parse sender EndpointAddr")?;

    let result = pull(
        &offer.hash,
        &offer.file_name,
        sender_addr,
        &dest_dir,
        secret_key,
    )
    .await;

    let ack = match &result {
        Ok(()) => SyncAck { ok: true, error: None },
        Err(e) => SyncAck { ok: false, error: Some(e.to_string()) },
    };
    write_msg(&mut send, &ack).await.context("write SyncAck")?;
    let _ = send.finish();

    result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Import a single file into `store` as a single-entry `Collection` (HashSeq)
/// and return the collection's `Hash`.
async fn import_file_as_collection(store: &FsStore, path: &Path) -> anyhow::Result<Hash> {
    // Add the raw file blob.
    let temp_tag = store
        .add_path_with_opts(AddPathOptions {
            path: path.to_path_buf(),
            mode: ImportMode::TryReference,
            format: BlobFormat::Raw,
        })
        .temp_tag()
        .await
        .map_err(|e| anyhow::anyhow!("import error: {:?}", e))?;

    let file_hash = temp_tag.hash();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_owned();

    // Wrap in a single-entry Collection so the receiver can identify the blob.
    let collection = Collection::from_iter([(file_name, file_hash)]);
    let coll_tag = collection
        .store(store)
        .await
        .context("store collection")?;

    Ok(coll_tag.hash())
}

/// Connect to `peer` over `SYNC_ALPN`, send `offer`, and wait for `SyncAck`.
async fn notify_peer(
    endpoint: &Endpoint,
    peer: &EndpointAddr,
    offer: &SyncOffer,
) -> anyhow::Result<()> {
    let connection = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint.connect(peer.clone(), SYNC_ALPN),
    )
    .await
    .context("connect timeout to peer")?
    .context("connect to peer")?;

    let (mut send, mut recv) = connection.open_bi().await?;
    write_msg(&mut send, offer).await?;
    let _ = send.finish();

    let ack: SyncAck = tokio::time::timeout(Duration::from_secs(120), read_msg(&mut recv))
        .await
        .context("timeout waiting for SyncAck")?
        .context("read SyncAck")?;

    if !ack.ok {
        anyhow::bail!(
            "peer reported sync error: {}",
            ack.error.unwrap_or_else(|| "unknown".to_owned())
        );
    }
    Ok(())
}

/// Random suffix for temp directory names.
fn nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}-{}", std::process::id(), ns)
}

/// RAII guard that removes a temp directory on drop (best-effort).
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let path = self.0.clone();
        std::thread::spawn(move || {
            let _ = std::fs::remove_dir_all(&path);
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn test_key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn write_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    // ------------------------------------------------------------------
    // EndpointAddrWire round-trip (IP-only, no relay)
    // ------------------------------------------------------------------

    #[test]
    fn endpoint_addr_wire_roundtrip() {
        let key = test_key(1);
        let node_id = key.public();
        let sa: std::net::SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let addr = EndpointAddr::new(node_id).with_ip_addr(sa);

        let wire = EndpointAddrWire::from_endpoint_addr(&addr);
        assert_eq!(wire.node_id, node_id.to_string());
        assert_eq!(wire.addrs, vec!["127.0.0.1:4242"]);
        assert!(wire.relay_url.is_none());

        let addr2 = wire.to_endpoint_addr().unwrap();
        assert_eq!(addr2.id, node_id);
    }

    // ------------------------------------------------------------------
    // import_file_as_collection produces a non-zero hash
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn import_file_returns_non_empty_hash() {
        let tmp = TempDir::new().unwrap();
        let file = write_test_file(tmp.path(), "hello.txt", b"hello world");

        let store_dir = tmp.path().join("store");
        tokio::fs::create_dir_all(&store_dir).await.unwrap();
        let fs_store = FsStore::load(&store_dir).await.unwrap();

        let hash = import_file_as_collection(&fs_store, &file).await.unwrap();
        assert_ne!(hash, Hash::EMPTY);
    }

    // ------------------------------------------------------------------
    // Unsafe file name is rejected by pull before any network I/O
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn pull_rejects_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let key = test_key(5);
        // Use a well-formed hash string (all zeros → doesn't matter, name check fires first).
        let dummy_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let dummy_addr = EndpointAddr::new(key.public());
        let err = pull(dummy_hash, "../evil.txt", dummy_addr, tmp.path(), key)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unsafe file name"),
            "unexpected error: {err}"
        );
    }

    // ------------------------------------------------------------------
    // TempDirGuard removes the directory on drop
    // ------------------------------------------------------------------

    #[test]
    fn temp_dir_guard_cleans_up() {
        let tmp = TempDir::new().unwrap();
        let guarded = tmp.path().join("guarded");
        std::fs::create_dir_all(&guarded).unwrap();
        assert!(guarded.exists());
        drop(TempDirGuard(guarded.clone()));
        // Give the spawned thread time to remove the dir.
        std::thread::sleep(Duration::from_millis(100));
        assert!(!guarded.exists(), "TempDirGuard did not remove {:?}", guarded);
    }

    // ------------------------------------------------------------------
    // Stream role: sender opens_bi, handler must accept_bi (not open_bi).
    //
    // Two loopback iroh endpoints, no relay.  We build the receiver's
    // EndpointAddr from its bound_sockets() so the sender can connect
    // without waiting for STUN/relay discovery.
    //
    // Test A proves accept_bi completes the round-trip within 5 s.
    // Test B proves open_bi (the original bug) deadlocks and times out.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn handler_accepts_stream_opened_by_sender() {
        // Bind a minimal loopback endpoint.  We use RelayMode::Disabled so
        // there is no relay overhead; bound_sockets() gives us the actual
        // UDP port immediately after bind() completes.
        async fn make_endpoint(seed: u8) -> Endpoint {
            Endpoint::empty_builder()
                .secret_key(test_key(seed))
                .relay_mode(RelayMode::Disabled)
                .alpns(vec![SYNC_ALPN.to_vec()])
                .bind()
                .await
                .unwrap()
        }

        // Build an EndpointAddr that the sender can use to reach `ep`
        // directly on loopback, without relay.
        fn loopback_addr(ep: &Endpoint) -> EndpointAddr {
            let node_id = ep.id();
            let mut addr = EndpointAddr::new(node_id);
            for sa in ep.bound_sockets() {
                // Replace the unspecified address (0.0.0.0) with 127.0.0.1
                // so the peer reaches us over loopback.
                let loopback = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    sa.port(),
                );
                addr = addr.with_ip_addr(loopback);
            }
            addr
        }

        // Helper: connect from `from` to `to_addr`, open a bi stream, and
        // write a SyncOffer.  The SyncOffer's sender_addr points back at
        // `from` itself — when handle_sync_connection calls pull() it will
        // try to connect to `from` over iroh_blobs::ALPN, which `from` does
        // not serve, so the connection is rejected quickly (ALPN mismatch).
        // This lets pull() error out fast so the SyncAck is written promptly.
        async fn send_offer(
            from: &Endpoint,
            to_addr: EndpointAddr,
        ) -> iroh::endpoint::RecvStream {
            let conn = tokio::time::timeout(
                Duration::from_secs(5),
                from.connect(to_addr, SYNC_ALPN),
            )
            .await
            .expect("connect timed out")
            .expect("connect failed");

            let (mut send_stream, recv_stream) = conn.open_bi().await.unwrap();
            let offer = SyncOffer {
                // Invalid hash: pull() will fail to parse it immediately,
                // before any network I/O, so the SyncAck is written promptly.
                hash: "not-a-valid-hash".to_owned(),
                file_name: "test.txt".to_owned(),
                sender_addr: EndpointAddrWire {
                    node_id: test_key(99).public().to_string(),
                    addrs: vec![],
                    relay_url: None,
                },
            };
            write_msg(&mut send_stream, &offer).await.unwrap();
            let _ = send_stream.finish();
            recv_stream
        }

        // ---- Test A: production handle_sync_connection gets a SyncAck back --
        //
        // We call the real handler.  The SyncOffer points pull() at a loopback
        // address that immediately refuses the connection, so pull() fails
        // fast and the handler still writes a SyncAck { ok: false }.  The
        // important property under test is that the ack arrives at all — which
        // requires the handler to call accept_bi (not open_bi) to read the
        // offer first.
        {
            let recv_ep = make_endpoint(40).await;
            let recv_addr = loopback_addr(&recv_ep);
            let recv_ep_task = recv_ep.clone();
            let recv_key = test_key(40);
            let dest = TempDir::new().unwrap();
            let dest_path = dest.path().to_path_buf();
            let server = tokio::spawn(async move {
                let incoming = recv_ep_task.accept().await.unwrap();
                // handle_sync_connection is the production code under test.
                let _ = handle_sync_connection(incoming, dest_path, recv_key).await;
            });

            let send_ep = make_endpoint(41).await;
            let mut recv_stream = send_offer(&send_ep, recv_addr).await;

            let result = tokio::time::timeout(
                Duration::from_secs(5),
                read_msg::<SyncAck>(&mut recv_stream),
            )
            .await;
            server.abort();
            assert!(
                result.is_ok(),
                "handle_sync_connection: timed out waiting for SyncAck — \
                 handler likely called open_bi instead of accept_bi"
            );
            recv_ep.close().await;
        }

        // ---- Test B: conceptual proof — open_bi deadlocks, timeout fires ---
        //
        // A server-side task that calls open_bi (the original bug) will
        // deadlock: neither side writes first on the new stream, so both
        // block waiting.  The timeout confirms this property.
        {
            let recv_ep = make_endpoint(50).await;
            let recv_addr = loopback_addr(&recv_ep);
            let recv_ep_task = recv_ep.clone();
            let _server = tokio::spawn(async move {
                let incoming = recv_ep_task.accept().await.unwrap();
                let conn: Connection = incoming.await.unwrap();
                // BUG: open_bi opens a *new* stream; neither side writes first.
                let (_send, mut recv) = conn.open_bi().await.unwrap();
                let _: Result<SyncOffer, _> = read_msg(&mut recv).await;
            });

            let send_ep = make_endpoint(51).await;
            let mut recv_stream = send_offer(&send_ep, recv_addr).await;

            let result = tokio::time::timeout(
                Duration::from_secs(2),
                read_msg::<SyncAck>(&mut recv_stream),
            )
            .await;
            assert!(
                result.is_err(),
                "open_bi path: expected timeout (deadlock), but got a response"
            );
        }
    }

    // ------------------------------------------------------------------
    // End-to-end push → pull (in-process, two iroh endpoints)
    // Requires network access (uses iroh relay infrastructure).
    // ------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires network (iroh relay); run with --ignored"]
    async fn push_pull_roundtrip() {
        let sender_dir = TempDir::new().unwrap();
        let receiver_dir = TempDir::new().unwrap();

        let sender_key = test_key(10);
        let receiver_key = test_key(20);

        let content = b"dddatasync sync test payload";
        let src_file = write_test_file(sender_dir.path(), "sync_test.txt", content);

        // --- Receiver: set up a listener endpoint --------------------------
        let recv_endpoint = Endpoint::empty_builder()
            .secret_key(receiver_key.clone())
            .relay_mode(RelayMode::Default)
            .alpns(vec![SYNC_ALPN.to_vec(), iroh_blobs::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        // Wait for the receiver to be online.
        tokio::time::timeout(Duration::from_secs(30), async {
            let _ = recv_endpoint.online().await;
        })
        .await
        .unwrap();

        let recv_addr = recv_endpoint.addr();
        let recv_dest = receiver_dir.path().to_path_buf();
        let recv_key2 = receiver_key.clone();

        let listener = SyncListener::new(recv_endpoint, recv_dest.clone(), recv_key2);
        let listener_handle = tokio::spawn(listener.run());

        // --- Sender: push --------------------------------------------------
        push(&src_file, &[recv_addr], sender_key, sender_dir.path())
            .await
            .unwrap();

        // Give the listener time to finish the pull.
        tokio::time::sleep(Duration::from_millis(500)).await;
        listener_handle.abort();

        // --- Assert the file arrived on the receiver side ------------------
        let dest_file = recv_dest.join("sync_test.txt");
        assert!(dest_file.exists(), "synced file not found at {:?}", dest_file);
        let got = tokio::fs::read(&dest_file).await.unwrap();
        assert_eq!(got.as_slice(), content.as_slice());
    }
}
