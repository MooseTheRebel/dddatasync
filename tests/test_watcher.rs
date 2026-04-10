//! Layer 2 — In-process integration test for the watcher (Approach B).
//!
//! Spins up two `DddSync` + `SyncListener` + `Watcher` instances inside the
//! same process, each backed by a `tempfile::TempDir`.  A file written into
//! store-1's directory is detected by its `Watcher`, pushed over iroh to the
//! `SyncListener` on store-2, and should appear in store-2's directory.
//!
//! Uses `RelayMode::Default` so iroh can use its relay infrastructure for
//! loopback connectivity.  Marked `#[ignore]` because it requires outbound
//! network access to the iroh relay.
//!
//! Run with:
//!   cargo test --test test_watcher -- --ignored

use std::time::Duration;

use dddatasync::auth::UserIdentity;
use dddatasync::rendezvous_client::{PeerRecord, RendezvousClient, RegisterRequest};
use dddatasync::store::DddSync;
use dddatasync::sync::SyncListener;
use dddatasync::watcher::Watcher;
use iroh::{Endpoint, RelayMode, SecretKey};
use tempfile::TempDir;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helper: create a deterministic SecretKey from a seed byte
// ---------------------------------------------------------------------------

fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

// ---------------------------------------------------------------------------
// Helper: write a temp identity file so UserIdentity::load() works
// ---------------------------------------------------------------------------

fn write_identity(dir: &std::path::Path, username: &str, key: &SecretKey) {
    // Replicate the format used by auth::save_identity:
    //   "<username>\n<hex-encoded 32-byte key>\n"
    let key_hex: String = key.to_bytes().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    });
    let contents = format!("{}\n{}\n", username, key_hex);
    let path = dir.join(".identity");
    std::fs::write(&path, contents).unwrap();

    // Set 0600 so load_from_path doesn't reject it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires network (iroh relay); run with --ignored"]
async fn watcher_pushes_new_file_to_peer() {
    // -----------------------------------------------------------------------
    // Set up two temp store directories and write identities into them.
    // Both nodes share the same username so they appear as peers to each other.
    // They use *different* keys — same username, different devices.
    // -----------------------------------------------------------------------
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();

    let key1 = secret_key(10);
    let key2 = secret_key(20);
    let username = "testuser";

    write_identity(dir1.path(), username, &key1);
    write_identity(dir2.path(), username, &key2);

    let store1 = DddSync::open_at(dir1.path().to_path_buf()).unwrap();
    let _store2 = DddSync::open_at(dir2.path().to_path_buf()).unwrap();

    // -----------------------------------------------------------------------
    // Bind iroh endpoints for both nodes.
    // -----------------------------------------------------------------------
    let ep1 = Endpoint::empty_builder()
        .secret_key(key1.clone())
        .relay_mode(RelayMode::Default)
        .alpns(vec![dddatasync::sync::SYNC_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();

    let ep2 = Endpoint::empty_builder()
        .secret_key(key2.clone())
        .relay_mode(RelayMode::Default)
        .alpns(vec![dddatasync::sync::SYNC_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();

    // Wait for both endpoints to be online (relay connectivity established).
    tokio::time::timeout(Duration::from_secs(30), async {
        let _ = ep1.online().await;
    })
    .await
    .expect("ep1 did not come online");
    tokio::time::timeout(Duration::from_secs(30), async {
        let _ = ep2.online().await;
    })
    .await
    .expect("ep2 did not come online");

    // -----------------------------------------------------------------------
    // Build the peer records that the mock rendezvous will return.
    //
    // Node 1's watcher will ask "who are my peers?" and get node 2's address.
    // Node 2's watcher will ask "who are my peers?" and get node 1's address.
    // We capture the live EndpointAddr from the bound endpoints.
    // -----------------------------------------------------------------------
    let addr1 = ep1.addr();
    let addr2 = ep2.addr();

    let peer_record_for_node2 = PeerRecord {
        node_id: key2.public().to_string(),
        addrs: addr2.ip_addrs().map(|a| a.to_string()).collect(),
        relay_url: addr2.relay_urls().next().map(|u| u.to_string()),
        last_seen: 9999999999,
    };
    let peer_record_for_node1 = PeerRecord {
        node_id: key1.public().to_string(),
        addrs: addr1.ip_addrs().map(|a| a.to_string()).collect(),
        relay_url: addr1.relay_urls().next().map(|u| u.to_string()),
        last_seen: 9999999999,
    };

    let node1_id = key1.public().to_string();
    let node2_id = key2.public().to_string();

    // -----------------------------------------------------------------------
    // Start a mock rendezvous server.
    //
    // GET /peers?username=testuser returns the *other* node for each caller.
    // We use two separate MockServer instances — one per watcher — so we can
    // serve different peer lists without inspecting the caller's node_id from
    // the HTTP layer (the client filters its own node_id client-side, but we
    // want to be explicit here).
    // -----------------------------------------------------------------------
    let mock1 = MockServer::start().await;
    let mock2 = MockServer::start().await;

    // Node 1's rendezvous: returns node 2 as the peer.
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock1)
        .await;
    Mock::given(method("GET"))
        .and(path("/peers"))
        .and(query_param("username", username))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "peers": [peer_record_for_node2]
        })))
        .mount(&mock1)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/register"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock1)
        .await;

    // Node 2's rendezvous: returns node 1 as the peer.
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock2)
        .await;
    Mock::given(method("GET"))
        .and(path("/peers"))
        .and(query_param("username", username))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "peers": [peer_record_for_node1]
        })))
        .mount(&mock2)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/register"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock2)
        .await;

    // -----------------------------------------------------------------------
    // Spawn SyncListener on node 2 so it can receive pushed blobs.
    // -----------------------------------------------------------------------
    let listener2 = SyncListener::new(ep2.clone(), dir2.path().to_path_buf(), key2.clone());
    let _listener_handle = tokio::spawn(listener2.run());

    // -----------------------------------------------------------------------
    // Build the identity for node 1 directly from key1 so it uses the same
    // username and key as the mock rendezvous expects.
    // -----------------------------------------------------------------------
    let identity1 = UserIdentity::from_parts(username, key1.clone());

    // Re-register node 1 with its actual live address so the mock returns it
    // to node 2 correctly (already handled above by peer_record_for_node1).
    let _ = RendezvousClient::new(mock1.uri())
        .register(&RegisterRequest {
            username: identity1.username.clone(),
            node_id: node1_id,
            addrs: addr1.ip_addrs().map(|a| a.to_string()).collect(),
            relay_url: addr1.relay_urls().next().map(|u| u.to_string()),
        })
        .await;

    drop(node2_id); // only needed for peer_record construction above

    let watcher1 = Watcher::new(ep1, store1, identity1, mock1.uri());

    // -----------------------------------------------------------------------
    // Run the watcher in a background task; shut it down after the assertion.
    // -----------------------------------------------------------------------
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let watcher_handle = tokio::spawn(async move {
        watcher1
            .run(async move { shutdown_rx.await.ok(); })
            .await
            .unwrap();
    });

    // Give the watcher a moment to start and register.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // -----------------------------------------------------------------------
    // Write a file into store-1's directory and wait for it to appear on
    // store-2.
    // -----------------------------------------------------------------------
    let test_content = b"hello from watcher test";
    let src_path = dir1.path().join("watcher_test.txt");
    std::fs::write(&src_path, test_content).unwrap();

    let dest_path = dir2.path().join("watcher_test.txt");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if dest_path.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "watcher_test.txt did not appear in store-2 within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let got = std::fs::read(&dest_path).unwrap();
    assert_eq!(got, test_content, "file content mismatch after sync");

    // -----------------------------------------------------------------------
    // Clean up.
    // -----------------------------------------------------------------------
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), watcher_handle).await;
}
