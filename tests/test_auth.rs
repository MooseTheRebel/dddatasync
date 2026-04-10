/// Tests for `src/auth.rs` — `UserIdentity` login, load, key derivation, and
/// file-mode enforcement.
///
/// All tests use a temporary home-directory override so they never touch the
/// real `~/dddatasync/.identity`.  We do this by writing the identity
/// directly through the internal path helpers tested via the public API.
use dddatasync::auth::UserIdentity;
use std::fs;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helper: run the test closure with HOME pointing at a fresh temp dir.
// After the closure, HOME is restored.  Tests that modify HOME must NOT run
// in parallel with each other — Rust test harness runs tests in the same
// process on different threads, so we serialise with a global Mutex.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

static HOME_LOCK: Mutex<()> = Mutex::new(());

fn with_tmp_home<F: FnOnce(&TempDir)>(f: F) {
    let _guard = HOME_LOCK.lock().expect("HOME_LOCK poisoned");
    let tmp = tempfile::tempdir().expect("tempdir");
    let orig = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    f(&tmp);
    match orig {
        Some(h) => std::env::set_var("HOME", h),
        None => std::env::remove_var("HOME"),
    }
}

// ---------------------------------------------------------------------------
// KDF stability: same credentials → same NodeId, always.
// ---------------------------------------------------------------------------

#[test]
fn same_credentials_produce_same_node_id() {
    with_tmp_home(|_| {
        let id1 = UserIdentity::login("alice", "correct horse battery staple")
            .expect("first login");
        let node_id_1 = id1.node_id();

        // Delete the persisted identity so login re-derives from scratch.
        let home = std::env::var("HOME").unwrap();
        let identity_path = std::path::PathBuf::from(&home)
            .join("dddatasync")
            .join(".identity");
        fs::remove_file(&identity_path).expect("remove identity");

        let id2 = UserIdentity::login("alice", "correct horse battery staple")
            .expect("second login");

        assert_eq!(
            node_id_1,
            id2.node_id(),
            "same credentials must produce the same NodeId"
        );
    });
}

// ---------------------------------------------------------------------------
// KDF isolation: different credentials → different NodeId.
// ---------------------------------------------------------------------------

#[test]
fn different_credentials_produce_different_node_ids() {
    // Derive two keys in separate temp homes so we don't hit the "different
    // key already persisted" guard.
    let node_id_alice = {
        let _guard = HOME_LOCK.lock().expect("HOME_LOCK poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        let id = UserIdentity::login("alice", "passphrase").expect("login alice");
        let nid = id.node_id();
        std::env::remove_var("HOME");
        nid
    };

    let node_id_bob = {
        let _guard = HOME_LOCK.lock().expect("HOME_LOCK poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        let id = UserIdentity::login("bob", "passphrase").expect("login bob");
        let nid = id.node_id();
        std::env::remove_var("HOME");
        nid
    };

    assert_ne!(
        node_id_alice, node_id_bob,
        "different usernames must produce different NodeIds"
    );
}

#[test]
fn different_passphrases_produce_different_node_ids() {
    let node_id_a = {
        let _guard = HOME_LOCK.lock().expect("HOME_LOCK poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        let id = UserIdentity::login("charlie", "passphrase-one").expect("login");
        let nid = id.node_id();
        std::env::remove_var("HOME");
        nid
    };

    let node_id_b = {
        let _guard = HOME_LOCK.lock().expect("HOME_LOCK poisoned");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        let id = UserIdentity::login("charlie", "passphrase-two").expect("login");
        let nid = id.node_id();
        std::env::remove_var("HOME");
        nid
    };

    assert_ne!(
        node_id_a, node_id_b,
        "different passphrases must produce different NodeIds"
    );
}

// ---------------------------------------------------------------------------
// Idempotency: calling login twice with the same credentials is a no-op.
// ---------------------------------------------------------------------------

#[test]
fn login_is_idempotent_with_same_credentials() {
    with_tmp_home(|_| {
        let id1 = UserIdentity::login("dave", "s3cr3t").expect("first login");
        let id2 = UserIdentity::login("dave", "s3cr3t").expect("second login — must succeed");
        assert_eq!(id1.node_id(), id2.node_id());
    });
}

// ---------------------------------------------------------------------------
// Conflict detection: different credentials on existing identity must error.
// ---------------------------------------------------------------------------

#[test]
fn login_with_different_credentials_on_existing_identity_fails() {
    with_tmp_home(|_| {
        UserIdentity::login("eve", "first-passphrase").expect("first login");
        let err = UserIdentity::login("eve", "second-passphrase")
            .expect_err("should fail: different key would overwrite");
        let msg = err.to_string();
        assert!(
            msg.contains("different key") || msg.contains("re-enroll"),
            "unexpected error: {}", msg
        );
    });
}

// ---------------------------------------------------------------------------
// Load roundtrip: login then load returns the same NodeId.
// ---------------------------------------------------------------------------

#[test]
fn load_returns_same_node_id_as_login() {
    with_tmp_home(|_| {
        let id_login = UserIdentity::login("frank", "letmein").expect("login");
        let id_load = UserIdentity::load().expect("load");
        assert_eq!(
            id_login.node_id(),
            id_load.node_id(),
            "load() must return the same NodeId as login()"
        );
        assert_eq!(id_load.username, "frank");
    });
}

// ---------------------------------------------------------------------------
// Load without prior login must fail.
// ---------------------------------------------------------------------------

#[test]
fn load_without_login_fails() {
    with_tmp_home(|_| {
        let err = UserIdentity::load().expect_err("load without login should fail");
        // The error should be about the file not existing or a read failure.
        let _ = err; // just assert it returns Err
    });
}

// ---------------------------------------------------------------------------
// File mode: identity file must be written with mode 0600 (Unix only).
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn identity_file_has_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    with_tmp_home(|tmp| {
        UserIdentity::login("grace", "password").expect("login");
        let path = tmp.path().join("dddatasync").join(".identity");
        let meta = fs::metadata(&path).expect("stat identity");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity file must have mode 0600, got {:04o}", mode);
    });
}

// ---------------------------------------------------------------------------
// File mode: load must reject a world-readable identity file (Unix only).
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn load_rejects_world_readable_identity() {
    use std::os::unix::fs::PermissionsExt;

    with_tmp_home(|tmp| {
        UserIdentity::login("heidi", "password").expect("login");
        let path = tmp.path().join("dddatasync").join(".identity");

        // Chmod to 0644 (world-readable).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("chmod");

        let err = UserIdentity::load().expect_err("load of 0644 file must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("0600") || msg.contains("world-readable") || msg.contains("permissions"),
            "unexpected error: {}", msg
        );
    });
}
