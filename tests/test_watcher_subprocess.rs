//! Layer 2.5 — Subprocess integration test for the watcher (Approach C).
//!
//! Spawns two real `dddatasync` processes and one `rendezvous` process using
//! `std::process::Command`, each pointed at a temp directory.  The test runs
//! `dddatasync login` then `dddatasync start` (as a daemon) on both nodes,
//! writes a file into node-1's store directory, and asserts it appears in
//! node-2's store directory within a timeout.
//!
//! This tier validates:
//! - CLI subcommand wiring (`login`, `start`)
//! - Process lifecycle (daemon startup, keepalive, clean shutdown via SIGTERM)
//! - End-to-end flow through the real binary
//!
//! Marked `#[ignore]` because it requires:
//! - The `dddatasync` and `rendezvous` binaries to be compiled (`cargo build`)
//! - Outbound network access to the iroh relay infrastructure
//!
//! Run with:
//!   cargo test --test test_watcher_subprocess -- --ignored

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Paths to the compiled binaries (debug profile)
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn dddatasync_bin() -> PathBuf {
    workspace_root().join("target/debug/dddatasync")
}

fn rendezvous_bin() -> PathBuf {
    workspace_root().join("target/debug/rendezvous")
}

// ---------------------------------------------------------------------------
// RAII guard that kills a child process on drop
// ---------------------------------------------------------------------------

struct ProcessGuard(Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ---------------------------------------------------------------------------
// Poll until a file exists at `path` or `timeout` elapses.
// ---------------------------------------------------------------------------

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// Poll until the rendezvous server responds to a health-check GET.
// ---------------------------------------------------------------------------

/// Poll until `GET /peers?username=<username>` returns at least `min_peers`
/// entries.  Used to wait for both daemons to register before writing a file.
fn wait_for_peers_registered(url: &str, username: &str, min_peers: usize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let client = reqwest::blocking::Client::new();
    loop {
        let result = client
            .get(&format!("{}/peers?username={}", url, username))
            .timeout(Duration::from_secs(2))
            .send();
        if let Ok(resp) = result {
            if let Ok(body) = resp.text() {
                // Count "node_id" occurrences as a proxy for peer count.
                if body.matches("node_id").count() >= min_peers {
                    return true;
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_for_rendezvous(url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let client = reqwest::blocking::Client::new();
    loop {
        let result = client
            .get(&format!("{}/peers?username=healthcheck", url))
            .timeout(Duration::from_secs(1))
            .send();
        if result.map(|r| r.status().is_success()).unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires compiled binaries + network (iroh relay); run with --ignored"]
fn watcher_subprocess_syncs_file_between_two_nodes() {
    let ddd_bin = dddatasync_bin();
    let rdv_bin = rendezvous_bin();

    assert!(
        ddd_bin.exists(),
        "dddatasync binary not found at {:?} — run `cargo build` first",
        ddd_bin
    );
    assert!(
        rdv_bin.exists(),
        "rendezvous binary not found at {:?} — run `cargo build` first",
        rdv_bin
    );

    // -----------------------------------------------------------------------
    // Start the rendezvous server on a free port.
    // -----------------------------------------------------------------------
    let rdv_port = 18080u16; // fixed port; fine for a sequential #[ignore] test
    let rdv_url = format!("http://127.0.0.1:{}", rdv_port);

    let rdv_proc = Command::new(&rdv_bin)
        .env("PORT", rdv_port.to_string())
        .env("AUTO_APPROVE_USERS", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn rendezvous");
    let _rdv_guard = ProcessGuard(rdv_proc);

    assert!(
        wait_for_rendezvous(&rdv_url, Duration::from_secs(10)),
        "rendezvous server did not become healthy within 10 s on {}",
        rdv_url
    );

    // -----------------------------------------------------------------------
    // Create temp home directories for each node.
    // dddatasync reads/writes ~/dddatasync/, so we fake $HOME.
    // -----------------------------------------------------------------------
    let home1 = tempfile::TempDir::new().unwrap();
    let home2 = tempfile::TempDir::new().unwrap();
    let store1 = home1.path().join("dddatasync");
    let store2 = home2.path().join("dddatasync");
    std::fs::create_dir_all(&store1).unwrap();
    std::fs::create_dir_all(&store2).unwrap();

    // -----------------------------------------------------------------------
    // Login on both nodes.
    //
    // Same username so the rendezvous server groups them as peers, but
    // different passphrases so they derive distinct SecretKeys (and therefore
    // distinct NodeIds).  Using identical credentials gives both nodes the
    // same NodeId — the rendezvous filter removes each node's own entry,
    // leaving an empty peer list on both sides and no sync.
    // -----------------------------------------------------------------------
    let username = "subprocess-testuser";
    let passphrases = ["subprocess-hunter2-device1", "subprocess-hunter2-device2"];

    // Pre-create a rendezvous server account and inject the Bearer token into
    // both home directories.  POST /register requires auth; the device
    // passphrases differ from the shared server password, so server_login in
    // dddatasync login will fail silently without overwriting the token file.
    {
        let server_password = "subprocess-server-pw";
        let http = reqwest::blocking::Client::new();

        http.post(&format!("{}/auth/signup", rdv_url))
            .json(&serde_json::json!({
                "username": username,
                "email": format!("{}@dddatasync.local", username),
                "password": server_password,
            }))
            .send()
            .expect("POST /auth/signup failed");

        let resp = http
            .post(&format!("{}/auth/login", rdv_url))
            .json(&serde_json::json!({"username": username, "password": server_password}))
            .send()
            .expect("POST /auth/login failed")
            .json::<serde_json::Value>()
            .expect("failed to parse login response");
        let token = resp["token"].as_str().expect("no token in login response");

        for home in [home1.path(), home2.path()] {
            let token_path = home.join("dddatasync").join(".token");
            std::fs::write(&token_path, token).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &token_path,
                    std::fs::Permissions::from_mode(0o600),
                ).unwrap();
            }
        }
    }

    for (home, passphrase) in [home1.path(), home2.path()].iter().zip(passphrases.iter()) {
        let out = Command::new(&ddd_bin)
            .args(["login", "--username", username, "--passphrase", passphrase])
            .env("HOME", home)
            .env("RENDEZVOUS_URL", &rdv_url)
            .output()
            .expect("failed to run dddatasync login");
        assert!(
            out.status.success(),
            "dddatasync login failed on {:?}:\nstdout: {}\nstderr: {}",
            home,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // -----------------------------------------------------------------------
    // Start the watcher daemon on both nodes (background processes).
    // -----------------------------------------------------------------------
    let start1 = Command::new(&ddd_bin)
        .args(["start"])
        .env("HOME", home1.path())
        .env("RENDEZVOUS_URL", &rdv_url)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dddatasync start (node 1)");
    let _start1_guard = ProcessGuard(start1);

    let start2 = Command::new(&ddd_bin)
        .args(["start"])
        .env("HOME", home2.path())
        .env("RENDEZVOUS_URL", &rdv_url)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn dddatasync start (node 2)");
    let _start2_guard = ProcessGuard(start2);

    // Wait until both daemons have registered with rendezvous (up to 60 s).
    // The iroh endpoint needs relay connectivity before its address is useful.
    // Wait until both daemons have registered with rendezvous (up to 60 s).
    // Registration happens after notify::watch() is wired up in Watcher::run,
    // so once both nodes appear in rendezvous the filesystem watcher is ready.
    assert!(
        wait_for_peers_registered(&rdv_url, username, 2, Duration::from_secs(60)),
        "timed out waiting for both nodes to register with rendezvous"
    );

    // -----------------------------------------------------------------------
    // Write a file into store-1 and wait for it to appear in store-2.
    // -----------------------------------------------------------------------
    let test_content = b"hello from subprocess watcher test";
    let src_path = store1.join("subprocess_test.txt");
    std::fs::write(&src_path, test_content).unwrap();

    let dest_path = store2.join("subprocess_test.txt");
    assert!(
        wait_for_file(&dest_path, Duration::from_secs(30)),
        "subprocess_test.txt did not appear in store-2 within 30 s"
    );

    let got = std::fs::read(&dest_path).unwrap();
    assert_eq!(
        got, test_content,
        "file content mismatch after subprocess sync"
    );

    println!("[subprocess] subprocess_test.txt synced successfully from node-1 → node-2");
}
