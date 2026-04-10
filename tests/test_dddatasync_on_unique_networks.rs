//! Integration test: two dddatasync nodes on **isolated** Docker networks.
//!
//! Topology (forces iroh relay fallback / NAT traversal):
//! ```
//! Docker network: ddd-net1-<sfx>       Docker network: ddd-net2-<sfx>
//!   └── ddd-c1-<sfx>                     └── ddd-c2-<sfx>
//!         \                                       /
//!          └────── rendezvous-<sfx> ─────────────┘
//!                  (attached to both networks)
//! ```
//!
//! Because c1 and c2 are on different Docker networks they cannot reach each
//! other directly; all iroh data must flow through the public relay
//! infrastructure (or STUN hole-punch).  This exercises the relay-fallback
//! path described in PLAN.md.
//!
//! Test phases (per PLAN.md Step 8):
//! 1. Build binaries + create two isolated networks.
//! 2. Start rendezvous on net1, then connect it to net2.
//! 3. Start dddatasync containers — c1 on net1, c2 on net2.
//! 4. `dddatasync login` on both with identical credentials.
//! 5. `dddatasync start &` on both.
//! 6. Write a file on c1; assert it appears on c2 via the relay path.
//!
//! Run with:
//!   cargo test --test test_dddatasync_on_unique_networks -- --ignored

mod common;

use std::time::Duration;

const TEST_USERNAME: &str = "relayuser";
const TEST_PASSPHRASE: &str = "s3cr3t!";
const DDD_BIN: &str = "/usr/local/bin/dddatasync";
const STORE_DIR: &str = "/root/dddatasync";

#[test]
#[ignore = "requires Docker + external relay network access; run with --ignored"]
fn test_dddatasync_on_unique_networks() {
    // -----------------------------------------------------------------------
    // Phase 1 — Build & network setup
    // -----------------------------------------------------------------------
    let build = common::Build::compile();
    let sfx = common::unique_suffix();

    let net1 = format!("ddd-net1-{}", sfx);
    let net2 = format!("ddd-net2-{}", sfx);
    let c1_name = format!("ddd-c1-{}", sfx);
    let c2_name = format!("ddd-c2-{}", sfx);

    for net in [&net1, &net2] {
        let out = common::docker(&["network", "create", net]);
        assert!(
            out.status.success(),
            "docker network create {} failed:\n{}",
            net,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _net1_guard = common::NetworkGuard::new(net1.clone());
    let _net2_guard = common::NetworkGuard::new(net2.clone());

    // -----------------------------------------------------------------------
    // Phase 2 — Rendezvous: start on net1, then attach to net2
    //
    // RendezvousContainer::start handles both attachment steps.
    // -----------------------------------------------------------------------
    // Uses the Rust binary by default; set RENDEZVOUS_IMAGE to use a pre-built
    // image (e.g. rendezvous-py:latest for the Python implementation CI job).
    let _rendezvous = common::start_rendezvous(&build, &net1, &[&net2]);
    // The rendezvous container is reachable as "rendezvous-<sfx>" on both nets.
    // Use the container name as the hostname — Docker DNS resolves it per-network.
    let rendezvous_url = format!("http://{}:8080", _rendezvous.name);

    // -----------------------------------------------------------------------
    // Phase 3 — dddatasync containers (c1 on net1, c2 on net2)
    // -----------------------------------------------------------------------
    let c1_out = common::docker(&[
        "run", "-d",
        "--name", &c1_name,
        "--network", &net1,
        "--env", &format!("RENDEZVOUS_URL={}", rendezvous_url),
        common::ALPINE_IMAGE,
        "sleep", "600",
    ]);
    assert!(
        c1_out.status.success(),
        "docker run c1 failed:\n{}",
        String::from_utf8_lossy(&c1_out.stderr)
    );
    let _c1_guard = common::ContainerGuard::new(c1_name.clone());

    let c2_out = common::docker(&[
        "run", "-d",
        "--name", &c2_name,
        "--network", &net2,
        "--env", &format!("RENDEZVOUS_URL={}", rendezvous_url),
        common::ALPINE_IMAGE,
        "sleep", "600",
    ]);
    assert!(
        c2_out.status.success(),
        "docker run c2 failed:\n{}",
        String::from_utf8_lossy(&c2_out.stderr)
    );
    let _c2_guard = common::ContainerGuard::new(c2_name.clone());

    // Copy binaries in.
    common::copy_binary_to_container(&build.dddatasync, &c1_name, DDD_BIN);
    common::copy_binary_to_container(&build.dddatasync, &c2_name, DDD_BIN);

    // Ensure store dirs exist.
    for name in [&c1_name, &c2_name] {
        common::docker_exec(name, &format!("mkdir -p {}", STORE_DIR));
    }

    // -----------------------------------------------------------------------
    // Phase 4 — Login on both containers
    //
    // Different passphrases → distinct SecretKeys → distinct node IDs.
    // Same username → rendezvous groups them as peers.
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
    // Phase 5 — Start watcher daemons
    // -----------------------------------------------------------------------
    for name in [&c1_name, &c2_name] {
        let log_path = format!("/tmp/dddatasync-{}.log", name);
        let cmd = format!(
            "RUST_LOG=debug {} start > {} 2>&1 & echo $! > /tmp/dddatasync-{}.pid",
            DDD_BIN, log_path, name
        );
        let out = common::docker_exec(name, &cmd);
        println!(
            "[phase5] started daemon on {} (exit={})\n  stdout: {}\n  stderr: {}",
            name,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // Wait until rendezvous sees both nodes registered (up to 60 s).
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
            "[phase5] daemon on {} pid={}\n--- log ---\n{}--- end log ---",
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
            "[phase5] rendezvous /peers response: {}",
            String::from_utf8_lossy(&rdv_peers.stdout),
        );
    }

    assert!(both_registered, "timed out waiting for both nodes to register with rendezvous");

    // -----------------------------------------------------------------------
    // Phase 6 — Write a file on c1; assert it syncs to c2 via relay
    // -----------------------------------------------------------------------
    let test_content = "hello via relay path";
    let test_file_c1 = format!("{}/relay_test.txt", STORE_DIR);
    let test_file_c2 = format!("{}/relay_test.txt", STORE_DIR);

    let write_out = common::docker_exec(
        &c1_name,
        &format!("echo -n '{}' > {}", test_content, test_file_c1),
    );
    assert!(
        write_out.status.success(),
        "failed to write relay_test.txt on c1:\n{}",
        String::from_utf8_lossy(&write_out.stderr)
    );
    println!("[phase6] wrote test file to c1:{}", test_file_c1);

    // Relay path takes longer — allow up to 60 s.
    let appeared =
        common::wait_for_file(&c2_name, &test_file_c2, Duration::from_secs(60));

    // Always dump daemon logs before asserting.
    for name in [&c1_name, &c2_name] {
        let log_out = common::docker_exec(name, &format!("cat /tmp/dddatasync-{}.log 2>/dev/null || echo '(no log)'", name));
        println!(
            "[phase6] daemon log on {}:\n{}",
            name,
            String::from_utf8_lossy(&log_out.stdout),
        );
    }

    assert!(
        appeared,
        "relay_test.txt did not appear on c2 within 60 s (relay path)"
    );

    let got = common::read_file_in_container(&c2_name, &test_file_c2);
    assert_eq!(
        got.trim(),
        test_content,
        "synced file content mismatch on c2 (relay path): got {:?}",
        got
    );

    println!("[unique-networks] relay_test.txt synced successfully from c1 → c2 via relay");
}
