//! HTTP client for the rendezvous peer-discovery server.
//!
//! Provides:
//!   - `signup`       — POST /auth/signup  (create account)
//!   - `server_login` — POST /auth/login   (authenticate; returns Bearer token)
//!   - `register`     — POST /register     (upsert this device's NodeAddr)
//!   - `fetch_peers`  — GET  /peers        (list live peers for a username)
//!   - `deregister`   — DELETE /register   (best-effort clean shutdown)
//!
//! `signup` and `server_login` do not require a token.  All other mutating
//! operations require a `Bearer` token obtained from `server_login`.

use anyhow::Context;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Default URL (overridden by RENDEZVOUS_URL env var at runtime)
// ---------------------------------------------------------------------------

pub const DEFAULT_RENDEZVOUS_URL: &str = "https://rendezvous.example.com";

pub fn rendezvous_url() -> String {
    std::env::var("RENDEZVOUS_URL").unwrap_or_else(|_| DEFAULT_RENDEZVOUS_URL.to_owned())
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeregisterRequest {
    username: String,
    node_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerRecord {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
    pub last_seen: u64,
}

#[derive(Debug, Deserialize)]
struct PeersResponse {
    peers: Vec<PeerRecord>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RendezvousClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl RendezvousClient {
    /// Create a client with a bearer `token` for authenticated operations.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
            token: Some(token.into()),
        }
    }

    /// Create an unauthenticated client (for signup / login calls only).
    pub fn unauthenticated(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
            token: None,
        }
    }

    /// Create a client using the URL from `rendezvous_url()` and a stored token.
    pub fn from_env(token: impl Into<String>) -> Self {
        Self::new(rendezvous_url(), token)
    }

    fn bearer(&self) -> anyhow::Result<String> {
        self.token
            .as_ref()
            .map(|t| format!("Bearer {t}"))
            .ok_or_else(|| anyhow::anyhow!("not logged in — run `dddatasync login` first"))
    }

    // -----------------------------------------------------------------------
    // Auth operations (no token required)
    // -----------------------------------------------------------------------

    /// `POST /auth/signup` — create a new account on the rendezvous server.
    ///
    /// The server will send a verification email to `email`.  The account
    /// must be verified before `server_login` will succeed.
    pub async fn signup(&self, username: &str, email: &str, password: &str) -> anyhow::Result<()> {
        let url = format!("{}/auth/signup", self.base_url);
        let body = serde_json::json!({"username": username, "email": email, "password": password});
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("POST /auth/signup: send")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST /auth/signup returned {}: {}", status, text);
        }
        Ok(())
    }

    /// `POST /auth/login` — authenticate and return the bearer token string.
    pub async fn server_login(&self, username: &str, password: &str) -> anyhow::Result<String> {
        let url = format!("{}/auth/login", self.base_url);
        let body = serde_json::json!({"username": username, "password": password});
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("POST /auth/login: send")?;
        let status = resp.status();
        if status.as_u16() == 403 {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("login rejected: {}", text);
        }
        if !status.is_success() {
            anyhow::bail!("POST /auth/login returned {} — invalid credentials", status);
        }
        let json: serde_json::Value = resp.json().await.context("POST /auth/login: decode")?;
        json["token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("server returned no token"))
    }

    // -----------------------------------------------------------------------
    // Registry operations (Bearer token required)
    // -----------------------------------------------------------------------

    /// `POST /register` — enroll or refresh this device's address.
    pub async fn register(&self, req: &RegisterRequest) -> anyhow::Result<()> {
        let url = format!("{}/register", self.base_url);
        let auth = self.bearer()?;
        let resp = self
            .http
            .post(&url)
            .header("Authorization", auth)
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

    /// `GET /peers?username=<name>` — return all live peers for `username`.
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
            Some(id) => envelope.peers.into_iter().filter(|p| p.node_id != id).collect(),
            None => envelope.peers,
        };
        Ok(peers)
    }

    /// `DELETE /register` — remove this device on clean shutdown.  Best-effort.
    pub async fn deregister(&self, username: &str, node_id: &str) {
        let Ok(auth) = self.bearer() else { return };
        let url = format!("{}/register", self.base_url);
        let req = DeregisterRequest {
            username: username.to_owned(),
            node_id: node_id.to_owned(),
        };
        match self
            .http
            .delete(&url)
            .header("Authorization", auth)
            .json(&req)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => tracing::warn!(status = %resp.status(), "DELETE /register: unexpected status"),
            Err(e) => tracing::warn!(error = %e, "DELETE /register: send failed"),
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

    async fn setup() -> (MockServer, RendezvousClient) {
        let server = MockServer::start().await;
        let client = RendezvousClient::new(server.uri(), "test-token");
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
    // signup
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn signup_success() {
        let (server, _) = setup().await;
        let client = RendezvousClient::unauthenticated(server.uri());
        Mock::given(method("POST"))
            .and(path("/auth/signup"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        client.signup("alice", "alice@example.com", "pw").await.unwrap();
    }

    #[tokio::test]
    async fn signup_conflict_propagates() {
        let (server, _) = setup().await;
        let client = RendezvousClient::unauthenticated(server.uri());
        Mock::given(method("POST"))
            .and(path("/auth/signup"))
            .respond_with(ResponseTemplate::new(409).set_body_string("username already taken"))
            .mount(&server)
            .await;
        let err = client.signup("alice", "alice@example.com", "pw").await.unwrap_err();
        assert!(err.to_string().contains("409"), "expected 409: {err}");
    }

    // ------------------------------------------------------------------
    // server_login
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn server_login_returns_token() {
        let (server, _) = setup().await;
        let client = RendezvousClient::unauthenticated(server.uri());
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "abc123"})))
            .mount(&server)
            .await;
        let token = client.server_login("alice", "pw").await.unwrap();
        assert_eq!(token, "abc123");
    }

    #[tokio::test]
    async fn server_login_bad_credentials_propagates() {
        let (server, _) = setup().await;
        let client = RendezvousClient::unauthenticated(server.uri());
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let err = client.server_login("alice", "wrong").await.unwrap_err();
        assert!(err.to_string().contains("401"), "expected 401: {err}");
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
        assert!(err.to_string().contains("500"), "expected 500: {err}");
    }

    // ------------------------------------------------------------------
    // fetch_peers
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn fetch_peers_returns_list() {
        let (server, client) = setup().await;
        let body = serde_json::json!({
            "peers": [
                {"node_id": "n1", "addrs": ["10.0.0.1:1"], "relay_url": null, "last_seen": 1},
                {"node_id": "n2", "addrs": ["10.0.0.2:2"], "relay_url": null, "last_seen": 2}
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
    }

    #[tokio::test]
    async fn fetch_peers_filters_own_node_id() {
        let (server, client) = setup().await;
        let body = serde_json::json!({
            "peers": [
                {"node_id": "me",    "addrs": [], "relay_url": null, "last_seen": 1},
                {"node_id": "other", "addrs": [], "relay_url": null, "last_seen": 2}
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

    // ------------------------------------------------------------------
    // deregister
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn deregister_success_is_silent() {
        let (server, client) = setup().await;
        Mock::given(method("DELETE"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
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
        client.deregister("alice", "node-abc").await;
    }
}
