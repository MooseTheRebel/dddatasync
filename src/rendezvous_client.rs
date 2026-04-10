//! HTTP client for the rendezvous peer-discovery server.
//!
//! Provides three operations that mirror the server's REST API:
//!   - `register`   — POST /register  (upsert this device's NodeAddr)
//!   - `fetch_peers`— GET  /peers     (list live peers for a username)
//!   - `deregister` — DELETE /register (best-effort clean shutdown)
//!
//! The client is a thin wrapper around `reqwest`; all network errors are
//! surfaced as `anyhow::Error`.  No retries — callers are responsible for
//! applying backoff (e.g. the keepalive loop in `watcher.rs`).
//!
//! The rendezvous server URL is resolved at runtime from, in order:
//!   1. The `RENDEZVOUS_URL` environment variable (useful in tests / CI).
//!   2. The compile-time constant `DEFAULT_RENDEZVOUS_URL`.

use anyhow::Context;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Default URL (overridden by RENDEZVOUS_URL env var at runtime)
// ---------------------------------------------------------------------------

pub const DEFAULT_RENDEZVOUS_URL: &str = "https://rendezvous.example.com";

/// Return the rendezvous base URL to use, checking `RENDEZVOUS_URL` first.
pub fn rendezvous_url() -> String {
    std::env::var("RENDEZVOUS_URL").unwrap_or_else(|_| DEFAULT_RENDEZVOUS_URL.to_owned())
}

// ---------------------------------------------------------------------------
// Wire types — the REST API contract
//
// These types define the language-agnostic JSON contract between the
// dddatasync client and any rendezvous server implementation (Rust, Go,
// Python, etc.).  The server must honour the same field names and shapes.
//
// REST API:
//   POST   /register  — body: RegisterRequest  → 200 OK
//   GET    /peers     — query: ?username=<name> → 200 { "peers": [...] }
//   DELETE /register  — body: DeregisterRequest → 200 OK
// ---------------------------------------------------------------------------

/// Body sent by `register` and (partially) by `deregister`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
}

/// Body sent by `deregister`.
#[derive(Debug, Serialize)]
struct DeregisterRequest {
    username: String,
    node_id: String,
}

/// A single peer record returned by `GET /peers`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerRecord {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
    pub last_seen: u64,
}

/// Response envelope from `GET /peers`.
#[derive(Debug, Deserialize)]
struct PeersResponse {
    peers: Vec<PeerRecord>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Lightweight wrapper around a `reqwest::Client` pinned to one base URL.
#[derive(Debug, Clone)]
pub struct RendezvousClient {
    base_url: String,
    http: reqwest::Client,
}

impl RendezvousClient {
    /// Create a client targeting `base_url` (no trailing slash).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a client using the URL from `rendezvous_url()`.
    pub fn from_env() -> Self {
        Self::new(rendezvous_url())
    }

    /// `POST /register` — enroll or refresh this device's address.
    pub async fn register(&self, req: &RegisterRequest) -> anyhow::Result<()> {
        let url = format!("{}/register", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .context("POST /register: send")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST /register returned {}: {}", status, body);
        }
        Ok(())
    }

    /// `GET /peers?username=<name>` — return all live peers for `username`,
    /// excluding the peer whose `node_id` equals `own_node_id` (if given).
    pub async fn fetch_peers(
        &self,
        username: &str,
        own_node_id: Option<&str>,
    ) -> anyhow::Result<Vec<PeerRecord>> {
        let url = format!("{}/peers", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("username", username)])
            .send()
            .await
            .context("GET /peers: send")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET /peers returned {}: {}", status, body);
        }
        let envelope: PeersResponse = resp.json().await.context("GET /peers: decode JSON")?;
        let peers = match own_node_id {
            Some(id) => envelope
                .peers
                .into_iter()
                .filter(|p| p.node_id != id)
                .collect(),
            None => envelope.peers,
        };
        Ok(peers)
    }

    /// `DELETE /register` — remove this device on clean shutdown.
    /// Best-effort: errors are logged but not propagated.
    pub async fn deregister(&self, username: &str, node_id: &str) {
        let url = format!("{}/register", self.base_url);
        let req = DeregisterRequest {
            username: username.to_owned(),
            node_id: node_id.to_owned(),
        };
        match self.http.delete(&url).json(&req).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "DELETE /register: unexpected status");
            }
            Err(e) => {
                tracing::warn!(error = %e, "DELETE /register: send failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Helper: start a mock server and point a client at it.
    async fn setup() -> (MockServer, RendezvousClient) {
        let server = MockServer::start().await;
        let client = RendezvousClient::new(server.uri());
        (server, client)
    }

    fn sample_register() -> RegisterRequest {
        RegisterRequest {
            username: "alice".to_owned(),
            node_id: "node-abc".to_owned(),
            addrs: vec!["1.2.3.4:1234".to_owned()],
            relay_url: Some("https://relay.example.com".to_owned()),
        }
    }

    // ------------------------------------------------------------------
    // register
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn register_success() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        client.register(&sample_register()).await.unwrap();
    }

    #[tokio::test]
    async fn register_server_error_propagates() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let err = client.register(&sample_register()).await.unwrap_err();
        assert!(err.to_string().contains("500"), "expected 500 in error: {err}");
    }

    // ------------------------------------------------------------------
    // fetch_peers
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn fetch_peers_returns_list() {
        let (server, client) = setup().await;
        let body = serde_json::json!({
            "peers": [
                { "node_id": "n1", "addrs": ["10.0.0.1:1"], "relay_url": null, "last_seen": 1 },
                { "node_id": "n2", "addrs": ["10.0.0.2:2"], "relay_url": null, "last_seen": 2 }
            ]
        });
        Mock::given(method("GET"))
            .and(path("/peers"))
            .and(query_param("username", "alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let peers = client.fetch_peers("alice", None).await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].node_id, "n1");
        assert_eq!(peers[1].node_id, "n2");
    }

    #[tokio::test]
    async fn fetch_peers_filters_own_node_id() {
        let (server, client) = setup().await;
        let body = serde_json::json!({
            "peers": [
                { "node_id": "me",    "addrs": [], "relay_url": null, "last_seen": 1 },
                { "node_id": "other", "addrs": [], "relay_url": null, "last_seen": 2 }
            ]
        });
        Mock::given(method("GET"))
            .and(path("/peers"))
            .and(query_param("username", "alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let peers = client.fetch_peers("alice", Some("me")).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "other");
    }

    #[tokio::test]
    async fn fetch_peers_empty_list() {
        let (server, client) = setup().await;
        let body = serde_json::json!({ "peers": [] });
        Mock::given(method("GET"))
            .and(path("/peers"))
            .and(query_param("username", "healthcheck"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let peers = client.fetch_peers("healthcheck", None).await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn fetch_peers_server_error_propagates() {
        let (server, client) = setup().await;
        Mock::given(method("GET"))
            .and(path("/peers"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;

        let err = client.fetch_peers("alice", None).await.unwrap_err();
        assert!(err.to_string().contains("503"), "expected 503 in error: {err}");
    }

    // ------------------------------------------------------------------
    // deregister — best-effort, never panics
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn deregister_success_is_silent() {
        let (server, client) = setup().await;
        Mock::given(method("DELETE"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        // Should not panic or return an error.
        client.deregister("alice", "node-abc").await;
    }

    #[tokio::test]
    async fn deregister_error_is_silent() {
        let (server, client) = setup().await;
        Mock::given(method("DELETE"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        // Errors are swallowed (best-effort).
        client.deregister("alice", "node-abc").await;
    }
}
