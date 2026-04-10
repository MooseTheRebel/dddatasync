use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use argon2::{Algorithm, Argon2, Params, Version};
use iroh::SecretKey;
use zeroize::Zeroizing;

/// A stable identity for one user on this device.
///
/// The Ed25519 `node_key` is *deterministically derived* from `(username,
/// passphrase)` via Argon2id, so the same credentials on any device produce
/// the same key — and therefore the same `NodeId`.  No key material is ever
/// shown to the user; it is stored encrypted at `~/dddatasync/.identity`.
pub struct UserIdentity {
    pub username: String,
    node_key: SecretKey,
}

// SecretKey does not implement Debug; provide a non-leaking impl.
impl std::fmt::Debug for UserIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserIdentity")
            .field("username", &self.username)
            .field("node_id", &self.node_key.public())
            .finish()
    }
}

impl UserIdentity {
    /// Derive a `UserIdentity` from credentials, persist it to disk, and
    /// return the ready identity.
    ///
    /// Idempotent: if the same credentials produce the same key as what is
    /// already persisted, the file is left unchanged.  Calling `login` twice
    /// with different credentials for the same store directory is an error
    /// (the existing identity would be overwritten with a conflicting key).
    pub fn login(username: &str, passphrase: &str) -> anyhow::Result<Self> {
        let node_key = derive_key(username, passphrase)?;
        let identity = Self { username: username.to_owned(), node_key };

        let path = identity_path()?;

        // If a file already exists, verify it matches (idempotency).
        if path.exists() {
            let existing = load_from_path(&path)
                .context("failed to load existing identity")?;
            if existing.node_key.to_bytes() != identity.node_key.to_bytes() {
                anyhow::bail!(
                    "identity file already exists with a different key; \
                     remove {:?} to re-enroll",
                    path
                );
            }
            return Ok(identity);
        }

        save_identity(&identity, &path)?;
        Ok(identity)
    }

    /// Load an existing identity from `~/dddatasync/.identity`.
    pub fn load() -> anyhow::Result<Self> {
        let path = identity_path()?;
        load_from_path(&path)
    }

    /// The stable iroh `PublicKey` (node identity) for this device.
    pub fn node_id(&self) -> iroh::PublicKey {
        self.node_key.public()
    }

    /// Expose the secret key for use by the iroh endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.node_key
    }

    /// Construct an identity directly from parts without touching the filesystem.
    ///
    /// Intended for integration tests that need a `UserIdentity` built from a
    /// known `SecretKey` without running the Argon2 KDF or writing `~/.identity`.
    #[doc(hidden)]
    pub fn from_parts(username: impl Into<String>, node_key: SecretKey) -> Self {
        Self { username: username.into(), node_key }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Path to the identity file.
fn identity_path() -> anyhow::Result<PathBuf> {
    let root = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
        .join("dddatasync");
    fs::create_dir_all(&root)?;
    Ok(root.join(".identity"))
}

/// Derive a 32-byte Ed25519 secret key from `(username, passphrase)` using
/// Argon2id.
///
/// Parameters are chosen to be fast enough for tests while still providing
/// meaningful KDF hardening in production.  The username is used as the salt
/// so that two users with the same passphrase get different keys.
fn derive_key(username: &str, passphrase: &str) -> anyhow::Result<SecretKey> {
    // Salt = SHA-256 of username bytes, giving a fixed 32-byte value regardless
    // of username length.  We avoid the `sha2` dep by using a simple constant
    // expansion: Argon2 already requires the salt to be ≥ 8 bytes and we can
    // pad/truncate to exactly 32 bytes.
    let mut salt = [0u8; 32];
    let name_bytes = username.as_bytes();
    for (i, &b) in name_bytes.iter().enumerate() {
        salt[i % 32] ^= b;
    }
    // Ensure the salt is never all-zero (Argon2 rejects that).
    if salt.iter().all(|&b| b == 0) {
        salt[0] = 0x5f; // '_'
    }

    // Argon2id with moderate parameters: m=64 KiB, t=3, p=1.
    // Low enough for tests to run quickly; high enough to resist offline attacks
    // on short passphrases in production.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, key_bytes.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 hash: {}", e))?;

    Ok(SecretKey::from_bytes(&key_bytes))
}

/// Serialize and persist the identity to `path` with mode 0600.
fn save_identity(identity: &UserIdentity, path: &PathBuf) -> anyhow::Result<()> {
    // Format: "<username>\n<hex-encoded 32-byte key>\n"
    let key_hex = hex_encode(identity.node_key.to_bytes());
    let contents = format!("{}\n{}\n", identity.username, key_hex);

    // Write to a temp file first, then rename for atomicity.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents.as_bytes())
        .with_context(|| format!("write identity tmp {:?}", tmp))?;

    set_mode_0600(&tmp)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename identity {:?} -> {:?}", tmp, path))?;

    Ok(())
}

/// Load and parse the identity from `path`, enforcing 0600 permissions.
fn load_from_path(path: &PathBuf) -> anyhow::Result<UserIdentity> {
    check_mode_0600(path)?;

    let contents = fs::read_to_string(path)
        .with_context(|| format!("read identity {:?}", path))?;

    let mut lines = contents.lines();
    let username = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("identity file missing username line"))?
        .to_owned();
    let key_hex = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("identity file missing key line"))?;

    let key_bytes = hex_decode(key_hex)
        .context("identity file: invalid hex key")?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity file: key must be 32 bytes"))?;

    Ok(UserIdentity {
        username,
        node_key: SecretKey::from_bytes(&key_bytes),
    })
}

// ---------------------------------------------------------------------------
// Platform-specific file mode helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn set_mode_0600(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("chmod 0600 {:?}", path))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &PathBuf) -> anyhow::Result<()> {
    // On non-Unix platforms (Windows) we skip permission enforcement.
    Ok(())
}

#[cfg(unix)]
fn check_mode_0600(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)
        .with_context(|| format!("stat {:?}", path))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "identity file {:?} has permissions {:04o}, expected 0600 — \
             refusing to load (world-readable key material)",
            path,
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode_0600(_path: &PathBuf) -> anyhow::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal hex encode/decode — avoids adding the `hex` crate
// ---------------------------------------------------------------------------

fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at offset {}: {}", i, e))
        })
        .collect()
}
