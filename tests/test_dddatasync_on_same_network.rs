//! Integration test: two dddatasync nodes on the **same** Docker network.
//!
//! Topology:
//! ```
//! Docker network: ddd-same-net-<sfx>
//!   ├── ddd-c1-<sfx>        (dddatasync binary)
//!   ├── ddd-c2-<sfx>        (dddatasync binary)
//!   └── rendezvous-<sfx>    (rendezvous server, port 8080)
//! ```
//!
//! Test phases (per PLAN.md Step 8):
//! 1. Build binaries + spin up containers on the shared network.
//! 2. Run `dddatasync login` on both containers with identical credentials.
//! 3. Start the watcher daemon on both containers (`dddatasync start &`).
//! 4. Write a file on c1; assert it appears on c2 within a timeout.
//! 5. Assert a 4th-file attempt is rejected on c1.
//!
//! This test is `#[ignore]` because it requires Docker and a network-capable
//! environment.  Run it with:
//!   cargo test --test test_dddatasync_on_same_network -- --ignored

mod common;

use std::time::Duration;

const TEST_USERNAME: &str = "testuser";
const TEST_PASSPHRASE: &str = "hunter2";
const DDD_BIN: &str = "/usr/local/bin/dddatasync";
const STORE_DIR: &str = "/root/dddatasync";

#[test]
#[ignore = "requires Docker + network; run with --ignored"]
fn test_dddatasync_on_same_network() {
    // -----------------------------------------------------------------------
    // Phase 1 — Build & container setup
    // -----------------------------------------------------------------------
    let build = common::Build::compile();
    let sfx = common::unique_suffix();

    let net_name = format!("ddd-same-net-{}", sfx);
    let c1_name = format!("ddd-c1-{}", sfx);
    let c2_name = format!("ddd-c2-{}", sfx);

    // Create the shared Docker network.
    let net_out = common::docker(&["network", "create", &net_name]);
    assert!(
        net_out.status.success(),
        "docker network create failed:\n{}",
        String::from_utf8_lossy(&net_out.stderr)
    );
    let _net_guard = common::NetworkGuard::new(net_name.clone());

    // Start the rendezvous container first and wait for it to be healthy.
    // Uses the Rust binary by default; set RENDEZVOUS_IMAGE to use a pre-built
    // image (e.g. rendezvous-py:latest for the Python implementation CI job).
    let _rendezvous = common::start_rendezvous(&build, &net_name, &[]);
    let rendezvous_url = format!("http://{}:8080", _rendezvous.name);

    // Start dddatasync containers.
    for name in [&c1_name, &c2_name] {
        let out = common::docker(&[
            "run", "-d",
            "--name", name,
            "--network", &net_name,
            "--env", &format!("RENDEZVOUS_URL={}", rendezvous_url),
            common::ALPINE_IMAGE,
            "sleep", "600",
        ]);
        assert!(
            out.status.success(),
            "docker run {} failed:\n{}",
            name,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _c1_guard = common::ContainerGuard::new(c1_name.clone());
    let _c2_guard = common::ContainerGuard::new(c2_name.clone());

    // Copy the dddatasync binary into both containers.
    common::copy_binary_to_container(&build.dddatasync, &c1_name, DDD_BIN);
    common::copy_binary_to_container(&build.dddatasync, &c2_name, DDD_BIN);

    // Ensure the store directory exists on both containers.
    for name in [&c1_name, &c2_name] {
        common::docker_exec(name, &format!("mkdir -p {}", STORE_DIR));
    }

    // -----------------------------------------------------------------------
    // Phase 2 — Login on both containers
    //
    // Each container gets a *different* passphrase so they derive distinct
    // iroh SecretKeys (and therefore distinct node IDs).  They share the same
    // username so the rendezvous server groups them as peers of each other.
    // Using identical credentials would give both nodes the same SecretKey,
    // causing the iroh relay to treat them as the same device and one of them
    // would fail to come online.
    // -----------------------------------------------------------------------
    let passphrases = [
        format!("{}-device1", TEST_PASSPHRASE),
        format!("{}-device2", TEST_PASSPHRASE),
    ];
    for (name, passphrase) in [&c1_name, &c2_name].iter().zip(passphrases.iter()) {
        let out = common::docker_exec(
            name,
            &format!(
                "{} login --username {} --passphrase {}",
                DDD_BIN, TEST_USERNAME, passphrase
            ),
        );
        assert!(
            out.status.success(),
            "dddatasync login failed on {}:\nstdout: {}\nstderr: {}",
            name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // -----------------------------------------------------------------------
    // Phase 3 — Start watcher daemon on both containers
    // -----------------------------------------------------------------------
    for name in [&c1_name, &c2_name] {
        // Log to a file so we can retrieve it after the test regardless of
        // whether the daemon is still running.
        let log_path = format!("/tmp/dddatasync-{}.log", name);
        let cmd = format!(
            "RUST_LOG=debug {} start > {} 2>&1 & echo $! > /tmp/dddatasync-{}.pid",
            DDD_BIN, log_path, name
        );
        let out = common::docker_exec(name, &cmd);
        println!(
            "[phase3] started daemon on {} (exit={})\n  stdout: {}\n  stderr: {}",
            name,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // Wait until rendezvous sees both nodes registered (up to 60 s — the
    // endpoint needs to come online and get a relay address first).
    let both_registered = common::wait_for_peers(
        &_rendezvous.name,
        2,
        TEST_USERNAME,
        Duration::from_secs(60),
    );

    // Print PID and current log lines regardless of registration outcome.
    for name in [&c1_name, &c2_name] {
        let pid_out = common::docker_exec(name, &format!("cat /tmp/dddatasync-{}.pid 2>/dev/null || echo '(no pid file)'", name));
        let log_out = common::docker_exec(name, &format!("cat /tmp/dddatasync-{}.log 2>/dev/null || echo '(no log)'", name));
        println!(
            "[phase3] daemon on {} pid={}\n--- log ---\n{}--- end log ---",
            name,
            String::from_utf8_lossy(&pid_out.stdout).trim(),
            String::from_utf8_lossy(&log_out.stdout),
        );
    }

    // Print final rendezvous peer list.
    {
        let rdv_peers = common::docker_exec(
            &_rendezvous.name,
            &format!("wget -qO- 'http://127.0.0.1:8080/peers?username={}' 2>/dev/null", TEST_USERNAME),
        );
        println!(
            "[phase3] rendezvous /peers response: {}",
            String::from_utf8_lossy(&rdv_peers.stdout),
        );
    }

    assert!(both_registered, "timed out waiting for both nodes to register with rendezvous");

    // -----------------------------------------------------------------------
    // Phase 4 — Write a file on c1; assert it appears on c2
    // -----------------------------------------------------------------------
    let test_content = "hello from c1 on same network";
    let test_file_on_c1 = format!("{}/sync_test.txt", STORE_DIR);
    let test_file_on_c2 = format!("{}/sync_test.txt", STORE_DIR);

    let write_out = common::docker_exec(
        &c1_name,
        &format!("echo -n '{}' > {}", test_content, test_file_on_c1),
    );
    assert!(
        write_out.status.success(),
        "failed to write test file on c1:\n{}",
        String::from_utf8_lossy(&write_out.stderr)
    );
    println!("[phase4] wrote test file to c1:{}", test_file_on_c1);

    // The watcher on c1 should detect the new file and push to c2.
    let appeared = common::wait_for_file(&c2_name, &test_file_on_c2, Duration::from_secs(30));

    // Always dump daemon logs before asserting, so we see what happened.
    for name in [&c1_name, &c2_name] {
        let log_out = common::docker_exec(name, &format!("cat /tmp/dddatasync-{}.log 2>/dev/null || echo '(no log)'", name));
        println!(
            "[phase4] daemon log on {}:\n{}",
            name,
            String::from_utf8_lossy(&log_out.stdout),
        );
    }

    assert!(
        appeared,
        "sync_test.txt did not appear on c2 within 30 s"
    );

    // Verify content integrity.
    let got = common::read_file_in_container(&c2_name, &test_file_on_c2);
    assert_eq!(
        got.trim(),
        test_content,
        "synced file content mismatch on c2: got {:?}",
        got
    );

    println!("[same-network] sync_test.txt synced successfully from c1 → c2");

    // -----------------------------------------------------------------------
    // Phase 5 — 4th-file attempt is rejected
    // -----------------------------------------------------------------------
    // Write three more files to fill the store on c1 (one already exists).
    for i in 2..=3 {
        let path = format!("{}/file{}.txt", STORE_DIR, i);
        let out = common::docker_exec(&c1_name, &format!("echo fill > {}", path));
        assert!(out.status.success(), "write fill file {} failed", i);
    }

    // Wait a beat for the watcher to process those additions.
    std::thread::sleep(Duration::from_secs(2));

    // Attempt to add a 4th file — the store limit should reject it.
    let fourth_file = format!("{}/overflow.txt", STORE_DIR);
    let reject_out = common::docker_exec(
        &c1_name,
        &format!("echo overflow > {} && echo WROTE", fourth_file),
    );
    // The shell echo redirect always succeeds; the *dddatasync* watcher should
    // log an error and not propagate the file.  Assert it does NOT appear on c2.
    std::thread::sleep(Duration::from_secs(5));
    let overflow_on_c2 = common::docker_exec(
        &c2_name,
        &format!("test -f {}/overflow.txt", STORE_DIR),
    );
    assert!(
        !overflow_on_c2.status.success(),
        "overflow.txt should NOT have synced to c2 (store limit)"
    );
    drop(reject_out); // suppress unused warning

    println!("[same-network] 4th-file limit enforced correctly");
}
