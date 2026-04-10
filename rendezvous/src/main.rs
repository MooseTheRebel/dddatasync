#![forbid(unsafe_code)]

//! Rendezvous server — a stateless peer-discovery phone book.
//!
//! API:
//!   POST   /register   — enroll or refresh a device's NodeAddr
//!   GET    /peers      — list all live peers for a username
//!   DELETE /register   — deregister a device on clean shutdown
//!
//! Storage is an in-memory `HashMap` protected by a `RwLock`.  Each entry
//! expires after `PEER_TTL_SECS` seconds; a background task prunes expired
//! entries every `PRUNE_INTERVAL_SECS` seconds.
//!
//! No secrets are stored — the rendezvous server is a phone book only.
//! iroh's public-key authentication rejects impostor connections regardless
//! of what is registered here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long a peer record is valid after its last `POST /register`.
const PEER_TTL_SECS: u64 = 300; // 5 minutes

/// How often the background task sweeps for expired records.
const PRUNE_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A single enrolled device as stored in the registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
    /// Unix timestamp (seconds) of the last registration.
    pub last_seen: u64,
}

/// Body for `POST /register` and `DELETE /register`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
}

/// Body for `DELETE /register` (only username + node_id needed).
#[derive(Debug, Deserialize)]
pub struct DeregisterRequest {
    pub username: String,
    pub node_id: String,
}

/// Response for `GET /peers`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerRecord>,
}

/// Query parameters for `GET /peers`.
#[derive(Debug, Deserialize)]
pub struct PeersQuery {
    pub username: String,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

pub type Registry = Arc<RwLock<HashMap<String, Vec<PeerRecord>>>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /register` — upsert a peer record for `username`.
async fn handle_register(
    State(registry): State<Registry>,
    Json(req): Json<RegisterRequest>,
) -> StatusCode {
    let record = PeerRecord {
        node_id: req.node_id.clone(),
        addrs: req.addrs,
        relay_url: req.relay_url,
        last_seen: now_secs(),
    };

    let mut map = registry.write().await;
    let peers = map.entry(req.username.clone()).or_default();

    // Update existing entry or push a new one.
    if let Some(existing) = peers.iter_mut().find(|p| p.node_id == req.node_id) {
        *existing = record;
    } else {
        peers.push(record);
    }

    info!(username = %req.username, node_id = %req.node_id, "registered");
    StatusCode::OK
}

/// `GET /peers?username=<name>` — return all live peers for `username`.
///
/// Returns an empty list (not 404) when the username is unknown — this is
/// intentional: the health-check endpoint (`?username=healthcheck`) relies on
/// getting a 200 with an empty list.
async fn handle_peers(
    State(registry): State<Registry>,
    Query(params): Query<PeersQuery>,
) -> Json<PeersResponse> {
    let map = registry.read().await;
    let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);

    let peers = map
        .get(&params.username)
        .map(|v| v.iter().filter(|p| p.last_seen >= cutoff).cloned().collect())
        .unwrap_or_default();

    Json(PeersResponse { peers })
}

/// `DELETE /register` — remove a specific peer on clean shutdown.
async fn handle_deregister(
    State(registry): State<Registry>,
    Json(req): Json<DeregisterRequest>,
) -> StatusCode {
    let mut map = registry.write().await;
    if let Some(peers) = map.get_mut(&req.username) {
        peers.retain(|p| p.node_id != req.node_id);
        if peers.is_empty() {
            map.remove(&req.username);
        }
    }
    info!(username = %req.username, node_id = %req.node_id, "deregistered");
    StatusCode::OK
}

// ---------------------------------------------------------------------------
// Background pruning task
// ---------------------------------------------------------------------------

async fn prune_task(registry: Registry) {
    let interval = Duration::from_secs(PRUNE_INTERVAL_SECS);
    loop {
        tokio::time::sleep(interval).await;
        let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);
        let mut map = registry.write().await;
        let before = map.values().map(|v| v.len()).sum::<usize>();
        map.retain(|_, peers| {
            peers.retain(|p| p.last_seen >= cutoff);
            !peers.is_empty()
        });
        let after = map.values().map(|v| v.len()).sum::<usize>();
        if before != after {
            info!(pruned = before - after, "pruned expired peer records");
        }
    }
}

// ---------------------------------------------------------------------------
// Router factory (pub so tests can reuse it without binding a port)
// ---------------------------------------------------------------------------

pub fn build_router(registry: Registry) -> Router {
    Router::new()
        .route("/register", post(handle_register))
        .route("/register", delete(handle_deregister))
        .route("/peers", get(handle_peers))
        .with_state(registry)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rendezvous=info".into()),
        )
        .init();

    let registry: Registry = Arc::new(RwLock::new(HashMap::new()));

    // Spawn the background pruning task.
    tokio::spawn(prune_task(Arc::clone(&registry)));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!(%addr, "rendezvous server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(registry)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    fn make_server() -> TestServer {
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        TestServer::new(build_router(registry))
    }

    // -----------------------------------------------------------------------
    // Health check: GET /peers with unknown username returns 200 + empty list.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn health_check_returns_200_empty_list() {
        let server = make_server();
        let res = server.get("/peers").add_query_param("username", "healthcheck").await;
        res.assert_status_ok();
        let body: PeersResponse = res.json();
        assert!(body.peers.is_empty());
    }

    // -----------------------------------------------------------------------
    // Register then fetch.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_and_fetch_peer() {
        let server = make_server();

        let req = serde_json::json!({
            "username": "alice",
            "node_id": "node-abc",
            "addrs": ["1.2.3.4:1234"],
            "relay_url": "https://relay.example.com"
        });
        server.post("/register").json(&req).await.assert_status_ok();

        let res = server.get("/peers").add_query_param("username", "alice").await;
        res.assert_status_ok();
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.peers[0].node_id, "node-abc");
        assert_eq!(body.peers[0].addrs, vec!["1.2.3.4:1234"]);
        assert_eq!(
            body.peers[0].relay_url.as_deref(),
            Some("https://relay.example.com")
        );
    }

    // -----------------------------------------------------------------------
    // Re-registering the same node_id updates the record (upsert).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_upserts_existing_node() {
        let server = make_server();

        let req1 = serde_json::json!({
            "username": "bob",
            "node_id": "node-bob",
            "addrs": ["10.0.0.1:9000"],
            "relay_url": null
        });
        server.post("/register").json(&req1).await.assert_status_ok();

        let req2 = serde_json::json!({
            "username": "bob",
            "node_id": "node-bob",
            "addrs": ["10.0.0.2:9001"],
            "relay_url": "https://relay.example.com"
        });
        server.post("/register").json(&req2).await.assert_status_ok();

        let res = server.get("/peers").add_query_param("username", "bob").await;
        let body: PeersResponse = res.json();
        // Must still be exactly one record (updated, not duplicated).
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.peers[0].addrs, vec!["10.0.0.2:9001"]);
        assert_eq!(
            body.peers[0].relay_url.as_deref(),
            Some("https://relay.example.com")
        );
    }

    // -----------------------------------------------------------------------
    // Multiple devices for the same user are all returned.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_devices_returned_for_same_user() {
        let server = make_server();

        for (node_id, addr) in [("node-1", "1.0.0.1:1"), ("node-2", "2.0.0.2:2")] {
            let req = serde_json::json!({
                "username": "carol",
                "node_id": node_id,
                "addrs": [addr],
                "relay_url": null
            });
            server.post("/register").json(&req).await.assert_status_ok();
        }

        let res = server.get("/peers").add_query_param("username", "carol").await;
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Users are isolated: alice's peers don't appear in bob's list.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn users_are_isolated() {
        let server = make_server();

        server.post("/register").json(&serde_json::json!({
            "username": "alice", "node_id": "a1", "addrs": [], "relay_url": null
        })).await.assert_status_ok();

        server.post("/register").json(&serde_json::json!({
            "username": "bob", "node_id": "b1", "addrs": [], "relay_url": null
        })).await.assert_status_ok();

        let res = server.get("/peers").add_query_param("username", "alice").await;
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.peers[0].node_id, "a1");
    }

    // -----------------------------------------------------------------------
    // DELETE /register removes the specific peer.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deregister_removes_peer() {
        let server = make_server();

        server.post("/register").json(&serde_json::json!({
            "username": "dave", "node_id": "d1", "addrs": [], "relay_url": null
        })).await.assert_status_ok();
        server.post("/register").json(&serde_json::json!({
            "username": "dave", "node_id": "d2", "addrs": [], "relay_url": null
        })).await.assert_status_ok();

        server.delete("/register").json(&serde_json::json!({
            "username": "dave", "node_id": "d1"
        })).await.assert_status_ok();

        let res = server.get("/peers").add_query_param("username", "dave").await;
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.peers[0].node_id, "d2");
    }

    // -----------------------------------------------------------------------
    // DELETE of a non-existent peer is a no-op (returns 200).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deregister_nonexistent_is_noop() {
        let server = make_server();
        server.delete("/register").json(&serde_json::json!({
            "username": "nobody", "node_id": "ghost"
        })).await.assert_status_ok();
    }

    // -----------------------------------------------------------------------
    // TTL: a peer with an old last_seen timestamp is excluded from GET /peers.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expired_peer_is_excluded_from_get_peers() {
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));

        // Manually insert a record with last_seen far in the past.
        {
            let mut map = registry.write().await;
            map.entry("eve".to_owned()).or_default().push(PeerRecord {
                node_id: "e1".to_owned(),
                addrs: vec![],
                relay_url: None,
                last_seen: 0, // epoch — definitely expired
            });
            // Also add a live record to confirm it is returned.
            map.entry("eve".to_owned()).or_default().push(PeerRecord {
                node_id: "e2".to_owned(),
                addrs: vec![],
                relay_url: None,
                last_seen: now_secs(),
            });
        }

        let server = TestServer::new(build_router(registry));
        let res = server.get("/peers").add_query_param("username", "eve").await;
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 1, "only the live record should be returned");
        assert_eq!(body.peers[0].node_id, "e2");
    }

    // -----------------------------------------------------------------------
    // Prune task removes expired entries from the registry.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn prune_removes_expired_entries() {
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));

        {
            let mut map = registry.write().await;
            map.entry("frank".to_owned()).or_default().push(PeerRecord {
                node_id: "f1".to_owned(),
                addrs: vec![],
                relay_url: None,
                last_seen: 0, // expired
            });
        }

        // Run a single prune cycle directly (don't wait for the background timer).
        {
            let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);
            let mut map = registry.write().await;
            map.retain(|_, peers| {
                peers.retain(|p| p.last_seen >= cutoff);
                !peers.is_empty()
            });
        }

        let map = registry.read().await;
        assert!(!map.contains_key("frank"), "expired username should be pruned");
    }
}
