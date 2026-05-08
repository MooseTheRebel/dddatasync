#![forbid(unsafe_code)]

//! Rendezvous server — peer-discovery phone book with user accounts.
//!
//! Public API:
//!   POST   /auth/signup          — create account (email + verification)
//!   POST   /auth/login           — authenticate; returns a Bearer token
//!   GET    /auth/verify/:token   — verify email address → account approved
//!
//! Protected API (Bearer token required):
//!   POST   /register             — enroll or refresh a device's NodeAddr
//!   DELETE /register             — deregister a device on clean shutdown
//!
//! Unauthenticated:
//!   GET    /peers                — list live peers for a username
//!
//! Environment variables:
//!   AUTO_APPROVE_USERS=true      — approve accounts immediately on signup
//!                                  (no email verification required)
//!   PORT                         — TCP port to listen on (default 8080)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PEER_TTL_SECS: u64 = 300;
const PRUNE_INTERVAL_SECS: u64 = 60;
const SESSION_TTL_SECS: u64 = 86_400; // 24 hours

// ---------------------------------------------------------------------------
// Peer data model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
    pub last_seen: u64,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub node_id: String,
    pub addrs: Vec<String>,
    pub relay_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeregisterRequest {
    pub username: String,
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerRecord>,
}

#[derive(Debug, Deserialize)]
pub struct PeersQuery {
    pub username: String,
}

// ---------------------------------------------------------------------------
// User account model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum AccountStatus {
    Pending,
    Approved,
    Blocked,
}

#[derive(Clone, Debug)]
pub struct UserAccount {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub status: AccountStatus,
    pub verification_token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub username: String,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

pub type Registry = Arc<RwLock<HashMap<String, Vec<PeerRecord>>>>;
pub type UserStore = Arc<RwLock<HashMap<String, UserAccount>>>;
pub type SessionStore = Arc<RwLock<HashMap<String, SessionRecord>>>;
pub type VerifyStore = Arc<RwLock<HashMap<String, String>>>;

#[derive(Clone)]
pub struct AppState {
    registry: Registry,
    users: UserStore,
    sessions: SessionStore,
    verify_tokens: VerifyStore,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn auto_approve() -> bool {
    std::env::var("AUTO_APPROVE_USERS")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Password and token helpers
// ---------------------------------------------------------------------------

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash_password: {}", e))?
        .to_string();
    Ok(hash)
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

// ---------------------------------------------------------------------------
// Bearer token authentication
// ---------------------------------------------------------------------------

async fn authenticate(headers: &HeaderMap, sessions: &SessionStore) -> Result<String, StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let map = sessions.read().await;
    let record = map.get(token).ok_or(StatusCode::UNAUTHORIZED)?;

    if record.expires_at < now_secs() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(record.username.clone())
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SignupRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// `POST /auth/signup`
async fn handle_signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let username = req.username.trim().to_owned();
    let email = req.email.trim().to_lowercase();
    let password = req.password;

    if username.is_empty() || email.is_empty() || password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "username, email, and password must be non-empty"})),
        ));
    }

    {
        let users = state.users.read().await;
        if users.contains_key(&username) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "username already taken"})),
            ));
        }
        if users.values().any(|u| u.email == email) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "email already registered"})),
            ));
        }
    }

    let password_hash = hash_password(&password).map_err(|e| {
        warn!(error = %e, "hash_password failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
    })?;

    let (status, verification_token) = if auto_approve() {
        (AccountStatus::Approved, None)
    } else {
        let tok = generate_token();
        (AccountStatus::Pending, Some(tok))
    };

    if let Some(ref tok) = verification_token {
        state.verify_tokens.write().await.insert(tok.clone(), username.clone());
        // Log the verification URL so operators can share it when SMTP is not configured.
        info!(
            username = %username,
            url = format!("/auth/verify/{}", tok),
            "verification link (send this to the user or configure SMTP)"
        );
    }

    state.users.write().await.insert(
        username.clone(),
        UserAccount {
            username: username.clone(),
            email,
            password_hash,
            status,
            verification_token,
        },
    );

    info!(%username, auto_approve = auto_approve(), "signup");

    let message = if auto_approve() {
        "Account created. You can now log in."
    } else {
        "Account created. Please check your email to verify your address."
    };

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"message": message})),
    ))
}

/// `GET /auth/verify/:token`
async fn handle_verify(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let username = {
        let mut verify = state.verify_tokens.write().await;
        verify.remove(&token).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "invalid or expired verification token"})),
            )
        })?
    };

    let mut users = state.users.write().await;
    if let Some(account) = users.get_mut(&username) {
        account.status = AccountStatus::Approved;
        account.verification_token = None;
        info!(%username, "email verified");
    }

    Ok(Json(serde_json::json!({"message": "Email verified. You can now log in."})))
}

/// `POST /auth/login`
async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let err_invalid = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid credentials"})),
        )
    };

    let (hash, status) = {
        let users = state.users.read().await;
        let account = users.get(&req.username).ok_or_else(err_invalid)?;
        (account.password_hash.clone(), account.status.clone())
    };

    if !verify_password(&req.password, &hash) {
        return Err(err_invalid());
    }

    match status {
        AccountStatus::Pending => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "account pending email verification — check your inbox"})),
            ));
        }
        AccountStatus::Blocked => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "account blocked"})),
            ));
        }
        AccountStatus::Approved => {}
    }

    let token = generate_token();
    state.sessions.write().await.insert(
        token.clone(),
        SessionRecord {
            username: req.username.clone(),
            expires_at: now_secs() + SESSION_TTL_SECS,
        },
    );

    info!(username = %req.username, "login");
    Ok(Json(serde_json::json!({"token": token})))
}

// ---------------------------------------------------------------------------
// Peer registry handlers
// ---------------------------------------------------------------------------

async fn handle_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    authenticate(&headers, &state.sessions).await?;

    let req: RegisterRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let record = PeerRecord {
        node_id: req.node_id.clone(),
        addrs: req.addrs,
        relay_url: req.relay_url,
        last_seen: now_secs(),
    };

    let mut map = state.registry.write().await;
    let peers = map.entry(req.username.clone()).or_default();
    if let Some(existing) = peers.iter_mut().find(|p| p.node_id == req.node_id) {
        *existing = record;
    } else {
        peers.push(record);
    }

    info!(username = %req.username, node_id = %req.node_id, "registered");
    Ok(StatusCode::OK)
}

async fn handle_peers(
    State(state): State<AppState>,
    Query(params): Query<PeersQuery>,
) -> Json<PeersResponse> {
    let map = state.registry.read().await;
    let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);

    let peers = map
        .get(&params.username)
        .map(|v| v.iter().filter(|p| p.last_seen >= cutoff).cloned().collect())
        .unwrap_or_default();

    Json(PeersResponse { peers })
}

async fn handle_deregister(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    authenticate(&headers, &state.sessions).await?;

    let req: DeregisterRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut map = state.registry.write().await;
    if let Some(peers) = map.get_mut(&req.username) {
        peers.retain(|p| p.node_id != req.node_id);
        if peers.is_empty() {
            map.remove(&req.username);
        }
    }
    info!(username = %req.username, node_id = %req.node_id, "deregistered");
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Background pruning
// ---------------------------------------------------------------------------

async fn prune_task(state: AppState) {
    let interval = Duration::from_secs(PRUNE_INTERVAL_SECS);
    loop {
        tokio::time::sleep(interval).await;
        let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);

        {
            let mut map = state.registry.write().await;
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

        {
            let now = now_secs();
            let mut sessions = state.sessions.write().await;
            let before = sessions.len();
            sessions.retain(|_, s| s.expires_at > now);
            let pruned = before - sessions.len();
            if pruned > 0 {
                info!(pruned, "pruned expired session tokens");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Router factory
// ---------------------------------------------------------------------------

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/signup", post(handle_signup))
        .route("/auth/login", post(handle_login))
        .route("/auth/verify/{token}", get(handle_verify))
        .route("/register", post(handle_register))
        .route("/register", delete(handle_deregister))
        .route("/peers", get(handle_peers))
        .with_state(state)
}

pub fn make_state() -> AppState {
    AppState {
        registry: Arc::new(RwLock::new(HashMap::new())),
        users: Arc::new(RwLock::new(HashMap::new())),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        verify_tokens: Arc::new(RwLock::new(HashMap::new())),
    }
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

    let state = make_state();
    tokio::spawn(prune_task(state.clone()));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!(%addr, auto_approve = auto_approve(), "rendezvous server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    fn make_server() -> TestServer {
        // Tests run with AUTO_APPROVE_USERS=true for simplicity.
        std::env::set_var("AUTO_APPROVE_USERS", "true");
        TestServer::new(build_router(make_state()))
    }

    async fn signup_and_login(server: &TestServer, username: &str) -> String {
        server
            .post("/auth/signup")
            .json(&serde_json::json!({
                "username": username,
                "email": format!("{username}@example.com"),
                "password": "hunter2"
            }))
            .await
            .assert_status(StatusCode::CREATED);

        let res = server
            .post("/auth/login")
            .json(&serde_json::json!({"username": username, "password": "hunter2"}))
            .await;
        res.assert_status_ok();
        res.json::<serde_json::Value>()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    // -----------------------------------------------------------------------
    // Signup
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn signup_creates_account() {
        let server = make_server();
        let res = server
            .post("/auth/signup")
            .json(&serde_json::json!({
                "username": "alice", "email": "alice@example.com", "password": "s3cr3t"
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
    }

    #[tokio::test]
    async fn duplicate_username_returns_409() {
        let server = make_server();
        let body = serde_json::json!({"username": "bob", "email": "bob@example.com", "password": "x"});
        server.post("/auth/signup").json(&body).await.assert_status(StatusCode::CREATED);
        server.post("/auth/signup").json(&body).await.assert_status(StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn duplicate_email_returns_409() {
        let server = make_server();
        server.post("/auth/signup").json(&serde_json::json!({
            "username": "carol", "email": "shared@example.com", "password": "x"
        })).await.assert_status(StatusCode::CREATED);
        server.post("/auth/signup").json(&serde_json::json!({
            "username": "carol2", "email": "shared@example.com", "password": "x"
        })).await.assert_status(StatusCode::CONFLICT);
    }

    // -----------------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn login_returns_token() {
        let server = make_server();
        let token = signup_and_login(&server, "dave").await;
        assert_eq!(token.len(), 64, "token should be 64 hex chars");
    }

    #[tokio::test]
    async fn login_bad_password_returns_401() {
        let server = make_server();
        server.post("/auth/signup").json(&serde_json::json!({
            "username": "eve", "email": "eve@example.com", "password": "correct"
        })).await;
        let res = server.post("/auth/login").json(&serde_json::json!({
            "username": "eve", "password": "wrong"
        })).await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_unknown_user_returns_401() {
        let server = make_server();
        let res = server.post("/auth/login").json(&serde_json::json!({
            "username": "nobody", "password": "x"
        })).await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Pending account (AUTO_APPROVE_USERS=false)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pending_account_cannot_login() {
        std::env::remove_var("AUTO_APPROVE_USERS");
        let server = TestServer::new(build_router(make_state()));

        server.post("/auth/signup").json(&serde_json::json!({
            "username": "frank", "email": "frank@example.com", "password": "pw"
        })).await.assert_status(StatusCode::CREATED);

        let res = server.post("/auth/login").json(&serde_json::json!({
            "username": "frank", "password": "pw"
        })).await;
        res.assert_status(StatusCode::FORBIDDEN);

        // Restore for other tests.
        std::env::set_var("AUTO_APPROVE_USERS", "true");
    }

    // -----------------------------------------------------------------------
    // Email verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_token_approves_account() {
        std::env::remove_var("AUTO_APPROVE_USERS");
        let state = make_state();
        let server = TestServer::new(build_router(state.clone()));

        server.post("/auth/signup").json(&serde_json::json!({
            "username": "grace", "email": "grace@example.com", "password": "pw"
        })).await.assert_status(StatusCode::CREATED);

        // Extract the verify token from state directly.
        let token = {
            let vt = state.verify_tokens.read().await;
            vt.keys().next().cloned().expect("verify token should exist")
        };

        server.get(&format!("/auth/verify/{token}")).await.assert_status_ok();

        // Should now be able to log in.
        server.post("/auth/login").json(&serde_json::json!({
            "username": "grace", "password": "pw"
        })).await.assert_status_ok();

        std::env::set_var("AUTO_APPROVE_USERS", "true");
    }

    #[tokio::test]
    async fn invalid_verify_token_returns_404() {
        let server = make_server();
        server.get("/auth/verify/deadbeef").await.assert_status(StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // Register / peers — require token
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_without_token_returns_401() {
        let server = make_server();
        let body = serde_json::to_vec(&serde_json::json!({
            "username": "alice", "node_id": "n1", "addrs": [], "relay_url": null
        })).unwrap();
        server
            .post("/register")
            .bytes(body.into())
            .content_type("application/json")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_and_fetch_peer() {
        let server = make_server();
        let token = signup_and_login(&server, "heidi").await;

        let body = serde_json::to_vec(&serde_json::json!({
            "username": "heidi",
            "node_id": "node-abc",
            "addrs": ["1.2.3.4:1234"],
            "relay_url": null
        })).unwrap();
        server
            .post("/register")
            .add_header("Authorization", format!("Bearer {token}"))
            .bytes(body.into())
            .content_type("application/json")
            .await
            .assert_status_ok();

        let res = server.get("/peers").add_query_param("username", "heidi").await;
        res.assert_status_ok();
        let body: PeersResponse = res.json();
        assert_eq!(body.peers.len(), 1);
        assert_eq!(body.peers[0].node_id, "node-abc");
    }

    #[tokio::test]
    async fn health_check_returns_200_empty_list() {
        let server = make_server();
        let res = server.get("/peers").add_query_param("username", "healthcheck").await;
        res.assert_status_ok();
        let body: PeersResponse = res.json();
        assert!(body.peers.is_empty());
    }

    // -----------------------------------------------------------------------
    // Prune
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn prune_removes_expired_entries() {
        let state = make_state();
        {
            let mut map = state.registry.write().await;
            map.entry("ivan".to_owned()).or_default().push(PeerRecord {
                node_id: "i1".to_owned(),
                addrs: vec![],
                relay_url: None,
                last_seen: 0,
            });
        }
        let cutoff = now_secs().saturating_sub(PEER_TTL_SECS);
        {
            let mut map = state.registry.write().await;
            map.retain(|_, peers| {
                peers.retain(|p| p.last_seen >= cutoff);
                !peers.is_empty()
            });
        }
        assert!(!state.registry.read().await.contains_key("ivan"));
    }
}
