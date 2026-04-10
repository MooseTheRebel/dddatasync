use dddatasync::store::{DddSync, MAX_FILE_BYTES, MAX_FILES};
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn make_store() -> (TempDir, DddSync) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = DddSync::open_at(dir.path().to_path_buf()).expect("open_at");
    (dir, store)
}

fn write_file(dir: &TempDir, name: &str, size: u64) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let data = vec![0u8; size as usize];
    fs::write(&path, &data).expect("write file");
    path
}

#[test]
fn cannot_add_more_than_3_files() {
    let src_dir = tempfile::tempdir().expect("src tempdir");
    let (_store_dir, store) = make_store();

    for i in 0..MAX_FILES {
        let path = write_file(&src_dir, &format!("file{}.bin", i), 1024);
        store.add(&path).expect("add should succeed");
    }

    // Adding a 4th file must fail.
    let extra = write_file(&src_dir, "extra.bin", 1024);
    let err = store.add(&extra).expect_err("4th add should fail");
    assert!(
        err.to_string().contains("limit"),
        "unexpected error message: {}", err
    );
}

#[test]
fn cannot_exceed_100_mb_per_file() {
    let src_dir = tempfile::tempdir().expect("src tempdir");
    let (_store_dir, store) = make_store();

    // can_add with exactly the limit is fine.
    store.can_add(MAX_FILE_BYTES).expect("at limit should be ok");

    // One byte over must fail.
    let err = store.can_add(MAX_FILE_BYTES + 1).expect_err("over limit should fail");
    assert!(
        err.to_string().contains("exceeds"),
        "unexpected error message: {}", err
    );

    // Also verify via add() with an oversized file.
    // Writing 100 MiB + 1 byte in a test is slow, so we verify via can_add() only.
    // add() delegates to can_add_locked() under the mutex, so both paths share
    // the same limit logic.
    let _ = src_dir; // keep alive
}

#[test]
fn add_then_remove_frees_slot() {
    let src_dir = tempfile::tempdir().expect("src tempdir");
    let (_store_dir, store) = make_store();

    // Fill to the limit.
    for i in 0..MAX_FILES {
        let path = write_file(&src_dir, &format!("file{}.bin", i), 512);
        store.add(&path).expect("add should succeed");
    }

    // Remove one file to free a slot.
    store.remove("file0.bin").expect("remove should succeed");

    // Now adding another file must succeed.
    let path = write_file(&src_dir, "new.bin", 512);
    store.add(&path).expect("add after remove should succeed");
}

#[test]
fn add_is_atomic_on_failure() {
    let src_dir = tempfile::tempdir().expect("src tempdir");
    let (_store_dir, store) = make_store();

    // Fill to the limit.
    for i in 0..MAX_FILES {
        let path = write_file(&src_dir, &format!("file{}.bin", i), 512);
        store.add(&path).expect("add should succeed");
    }

    // Attempt to add a 4th file — must fail.
    let extra = write_file(&src_dir, "extra.bin", 512);
    store.add(&extra).expect_err("should fail at limit");

    // The store must still have exactly MAX_FILES entries — no partial state.
    let files = store.files().expect("files()");
    assert_eq!(
        files.len(),
        MAX_FILES,
        "store should still have exactly {} files after failed add", MAX_FILES
    );
}

/// Rapid successive adds must not collide on temp file names.
/// Before the fix, uuid_simple() used subsec_nanos() which resets every second,
/// making collisions likely in tight loops.
#[test]
fn rapid_adds_do_not_collide_on_temp_names() {
    let src_dir = tempfile::tempdir().expect("src tempdir");
    let (_store_dir, store) = make_store();

    for i in 0..MAX_FILES {
        let path = write_file(&src_dir, &format!("rapid{}.bin", i), 512);
        store.add(&path).expect("rapid add should not collide");
    }

    let files = store.files().expect("files()");
    assert_eq!(files.len(), MAX_FILES, "all rapid adds should be present");
}

/// Concurrent adds from multiple threads must not allow the store to exceed MAX_FILES.
#[test]
fn concurrent_adds_do_not_exceed_limit() {
    use std::thread;

    let src_dir = Arc::new(tempfile::tempdir().expect("src tempdir"));
    let store_dir = tempfile::tempdir().expect("store tempdir");
    let store = Arc::new(
        DddSync::open_at(store_dir.path().to_path_buf()).expect("open_at"),
    );

    // Create more source files than MAX_FILES so threads have something to add.
    let thread_count = MAX_FILES * 3;
    let mut handles = Vec::new();

    for i in 0..thread_count {
        let src_dir = Arc::clone(&src_dir);
        let store = Arc::clone(&store);
        let path = {
            let p = src_dir.path().join(format!("concurrent{}.bin", i));
            fs::write(&p, vec![0u8; 512]).expect("write");
            p
        };
        handles.push(thread::spawn(move || store.add(&path)));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().expect("thread")).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    let files = store.files().expect("files()");
    assert!(
        files.len() <= MAX_FILES,
        "store has {} files, exceeds MAX_FILES ({})",
        files.len(),
        MAX_FILES
    );
    assert_eq!(
        successes,
        files.len(),
        "number of successful adds ({}) should equal files in store ({})",
        successes,
        files.len()
    );
    // keep dirs alive
    drop(store_dir);
}

/// `can_add()` is not atomic with `add()`: a `can_add()` approval is not a
/// reservation. This test proves that deterministically — thread A calls
/// `can_add()` (sees one free slot), then thread B fills that slot, then thread
/// A's subsequent `add()` must still fail because `add()` enforces the limit
/// independently. The fix is to make `can_add()` hold the store mutex so the
/// check and the commit are one atomic operation.
#[test]
fn can_add_approval_is_invalidated_by_concurrent_add() {
    use std::sync::Barrier;
    use std::thread;

    let src_dir = Arc::new(tempfile::tempdir().expect("src tempdir"));
    let store_dir = tempfile::tempdir().expect("store tempdir");
    let store = Arc::new(
        DddSync::open_at(store_dir.path().to_path_buf()).expect("open_at"),
    );

    // Fill to MAX_FILES - 1: one slot remains.
    for i in 0..(MAX_FILES - 1) {
        let p = src_dir.path().join(format!("pre{}.bin", i));
        fs::write(&p, vec![0u8; 512]).expect("write");
        store.add(&p).expect("pre-fill add");
    }

    // barrier_after_can_add: A signals B that can_add() returned Ok.
    // barrier_after_b_add:   B signals A that it has filled the last slot.
    let barrier_after_can_add = Arc::new(Barrier::new(2));
    let barrier_after_b_add = Arc::new(Barrier::new(2));

    let store_a = Arc::clone(&store);
    let store_b = Arc::clone(&store);
    let src_a = Arc::clone(&src_dir);
    let src_b = Arc::clone(&src_dir);
    let b1a = Arc::clone(&barrier_after_can_add);
    let b1b = Arc::clone(&barrier_after_can_add);
    let b2a = Arc::clone(&barrier_after_b_add);
    let b2b = Arc::clone(&barrier_after_b_add);

    let path_a = { let p = src_a.path().join("slot_a.bin"); fs::write(&p, vec![0u8; 512]).expect("write"); p };
    let path_b = { let p = src_b.path().join("slot_b.bin"); fs::write(&p, vec![0u8; 512]).expect("write"); p };

    let handle_a = thread::spawn(move || -> anyhow::Result<()> {
        store_a.can_add(512)?;   // sees one free slot — returns Ok
        b1a.wait();              // signal B: "I passed the check"
        b2a.wait();              // wait for B to fill the slot
        store_a.add(&path_a)    // slot is now gone — add() must fail
    });

    let handle_b = thread::spawn(move || -> anyhow::Result<()> {
        b1b.wait();              // wait until A has called can_add()
        store_b.add(&path_b)?;  // fill the last slot
        b2b.wait();
        Ok(())
    });

    let result_a = handle_a.join().expect("thread A panicked");
    let result_b = handle_b.join().expect("thread B panicked");

    result_b.expect("thread B should succeed filling the last slot");

    // A's can_add() said Ok, but add() must still reject because the slot
    // was taken. This is currently true because add() re-checks independently.
    // The bug is that can_add() alone is not a safe guard — it doesn't hold
    // the mutex, so any caller who relies on can_add() + add() as an atomic
    // check-then-act is racy.
    assert!(
        result_a.is_err(),
        "add() must reject even after can_add() returned Ok (slot was taken between calls)"
    );

    assert!(store.files().expect("files()").len() <= MAX_FILES);
    drop(store_dir);
}
