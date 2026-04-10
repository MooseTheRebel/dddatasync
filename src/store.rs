use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::warn;

pub const MAX_FILES: usize = 3;
pub const MAX_FILE_BYTES: u64 = 104_857_600; // 100 MiB

pub struct FileEntry {
    pub name: String,
    pub size: u64,
}

pub struct DddSync {
    root: PathBuf,
    mu: Mutex<()>,
}

impl DddSync {
    pub fn open() -> anyhow::Result<Self> {
        let root = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
            .join("dddatasync");
        fs::create_dir_all(&root)?;
        let store = Self { root, mu: Mutex::new(()) };
        // Warn about stale temp files left by a previous crash.
        let stale = store.temp_files()?;
        if !stale.is_empty() {
            warn!(
                count = stale.len(),
                "found stale .tmp-* files in store — run `dddatasync clean` to remove them"
            );
        }
        Ok(store)
    }

    /// For testing — open a store at an arbitrary path.
    pub fn open_at(root: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root, mu: Mutex::new(()) })
    }

    pub fn files(&self) -> anyhow::Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Skip dot-prefixed files (temp files, identity, lock, etc.)
            if name.starts_with('.') {
                continue;
            }
            let meta = entry.metadata()?;
            if meta.is_file() {
                entries.push(FileEntry { name, size: meta.len() });
            }
        }
        Ok(entries)
    }

    /// Returns an error if adding a file of `size` bytes would violate any limit.
    pub fn can_add(&self, size: u64) -> anyhow::Result<()> {
        let _guard = self.mu.lock().expect("store mutex poisoned");
        self.can_add_locked(size)
    }

    /// Limit checks with the mutex already held by the caller.
    fn can_add_locked(&self, size: u64) -> anyhow::Result<()> {
        if size > MAX_FILE_BYTES {
            anyhow::bail!(
                "file is {} bytes, which exceeds the {} byte per-file limit",
                size,
                MAX_FILE_BYTES
            );
        }
        let count = self.files()?.len();
        if count >= MAX_FILES {
            anyhow::bail!(
                "store already contains {} files (limit is {})",
                count,
                MAX_FILES
            );
        }
        Ok(())
    }

    /// Atomically copy `src` into the store. Fails if limits would be exceeded.
    pub fn add(&self, src: &Path) -> anyhow::Result<()> {
        let meta = fs::metadata(src)?;

        let name = src
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("source path has no file name"))?;

        let dest = self.root.join(name);

        // Copy to a temp file outside the lock so we don't hold it during I/O.
        let tmp_name = format!(".tmp-{}", uuid_simple());
        let tmp = self.root.join(&tmp_name);
        fs::copy(src, &tmp)?;

        // Hold the lock for the limit checks and the atomic rename.
        let _guard = self.mu.lock().expect("store mutex poisoned");

        if let Err(e) = self.can_add_locked(meta.len()) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        if dest.exists() {
            let _ = fs::remove_file(&tmp);
            anyhow::bail!("file {:?} already exists in the store", name);
        }

        fs::rename(&tmp, &dest)?;
        Ok(())
    }

    /// The root directory of this store.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Return the names of all `.tmp-*` entries under the store root.
    pub fn temp_files(&self) -> anyhow::Result<Vec<String>> {
        let mut temps = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".tmp-") {
                temps.push(name);
            }
        }
        Ok(temps)
    }

    /// Remove all `.tmp-*` entries under the store root.
    /// Returns the number of files removed.
    pub fn clean_temp_files(&self) -> anyhow::Result<usize> {
        let temps = self.temp_files()?;
        let count = temps.len();
        for name in &temps {
            let path = self.root.join(name);
            fs::remove_file(&path)?;
        }
        Ok(count)
    }

    pub fn remove(&self, name: &str) -> anyhow::Result<()> {
        let path = self.root.join(name);
        if !path.exists() {
            anyhow::bail!("file {:?} not found in store", name);
        }
        fs::remove_file(&path)?;
        Ok(())
    }
}

/// Minimal random suffix for temp file names — avoids pulling in uuid crate.
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    format!("{:08x}-{:016x}", std::process::id(), nanos)
}
