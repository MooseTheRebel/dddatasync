//! Shared test infrastructure for Docker-based integration tests.
//!
//! ## Key helpers
//!
//! - [`docker`]  — run an arbitrary `docker` sub-command and return the output.
//! - [`Build`]   — compile the `dddatasync` and `rendezvous` binaries for the
//!                 musl target used inside Alpine containers.
//! - [`ContainerGuard`] — RAII wrapper that calls `docker rm -f` on `Drop`,
//!                         preventing container leaks even when tests panic.
//! - [`NetworkGuard`]   — RAII wrapper that calls `docker network rm` on `Drop`.
//! - [`RendezvousContainer`] — start the rendezvous server in Docker, wait for
//!                             it to be healthy, and tear it down on `Drop`.
//! - [`wait_for_file`]  — poll a path inside a container until it appears or
//!                         a timeout elapses.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn cargo_bin() -> String {
    let host_arch = std::env::consts::ARCH;
    std::env::var("CARGO").unwrap_or_else(|_| {
        let rustup_home = std::env::var("RUSTUP_HOME")
            .unwrap_or_else(|_| format!("{}/.rustup", std::env::var("HOME").unwrap()));
        format!(
            "{}/toolchains/stable-{}-apple-darwin/bin/cargo",
            rustup_home, host_arch
        )
    })
}

pub fn augmented_path() -> String {
    let cargo_home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap()));
    let current_path = std::env::var("PATH").unwrap_or_default();
    format!("{}/bin:/opt/homebrew/bin:{}", cargo_home, current_path)
}

// ---------------------------------------------------------------------------
// docker() — low-level wrapper
// ---------------------------------------------------------------------------

/// Run `docker <args>` and return the `Output`. Never panics on failure —
/// callers decide whether to assert.
pub fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("docker {} failed to spawn: {}", args[0], e))
}

/// Run `docker exec <container> sh -c <cmd>` and return the output.
pub fn docker_exec(container: &str, cmd: &str) -> Output {
    docker(&["exec", container, "sh", "-c", cmd])
}

// ---------------------------------------------------------------------------
// Build helpers
// ---------------------------------------------------------------------------

/// Linux musl target derived from the host architecture.
pub fn linux_musl_target() -> String {
    let host_arch = std::env::consts::ARCH;
    format!("{}-unknown-linux-musl", host_arch)
}

/// Compiled paths for the two binaries.
pub struct Build {
    pub dddatasync: PathBuf,
    pub rendezvous: PathBuf,
}

impl Build {
    /// Build `dddatasync` and `rendezvous` for the musl target.
    /// Panics if the build fails or the expected binaries are missing.
    pub fn compile() -> Self {
        let root = workspace_root();
        let target = linux_musl_target();

        let status = Command::new(cargo_bin())
            .args(["zigbuild", "--release", "--workspace", "--target", &target])
            .env("PATH", augmented_path())
            .current_dir(&root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("failed to run cargo zigbuild");

        assert!(status.success(), "cargo zigbuild failed");

        let ddd = root.join(format!("target/{}/release/dddatasync", target));
        let rdv = root.join(format!("target/{}/release/rendezvous", target));

        assert!(ddd.exists(), "dddatasync binary missing at {:?}", ddd);
        assert!(rdv.exists(), "rendezvous binary missing at {:?}", rdv);

        Build {
            dddatasync: ddd,
            rendezvous: rdv,
        }
    }
}

// ---------------------------------------------------------------------------
// RAII guards
// ---------------------------------------------------------------------------

/// Calls `docker rm -f <name>` on drop, preventing container leaks.
pub struct ContainerGuard {
    pub name: String,
}

impl ContainerGuard {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        docker(&["rm", "-f", &self.name]);
    }
}

/// Calls `docker network rm <name>` on drop.
pub struct NetworkGuard {
    pub name: String,
}

impl NetworkGuard {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        docker(&["network", "rm", &self.name]);
    }
}

// ---------------------------------------------------------------------------
// Unique name generation (prevent collisions between parallel test runs)
// ---------------------------------------------------------------------------

/// Return a short random suffix to disambiguate container/network names.
pub fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}", ns ^ std::process::id())
}

// ---------------------------------------------------------------------------
// Alpine base image
// ---------------------------------------------------------------------------

pub const ALPINE_IMAGE: &str = "alpine:3.21";

// ---------------------------------------------------------------------------
// RendezvousContainer — start, health-check, tear down
// ---------------------------------------------------------------------------

/// A running rendezvous server inside Docker.
///
/// The container is attached to the networks passed to `start`. A `ContainerGuard`
/// ensures it is removed even if the test panics.
pub struct RendezvousContainer {
    // Held for RAII: `docker rm -f` fires on drop even if the test panics.
    #[allow(dead_code)]
    pub container: ContainerGuard,
    pub name: String,
    /// `http://127.0.0.1:<port>` — the rendezvous API reachable from the host.
    pub host_url: String,
}

impl RendezvousContainer {
    /// Start a rendezvous container on `first_network`, optionally also
    /// connecting it to `extra_networks` (for the unique-networks topology).
    ///
    /// Waits up to 10 s for the server to become healthy.
    pub fn start(
        binary: &PathBuf,
        first_network: &str,
        extra_networks: &[&str],
    ) -> Self {
        let sfx = unique_suffix();
        let name = format!("rendezvous-{}", sfx);

        // Copy binary to a temp path the container can reach via docker cp.
        let out = docker(&[
            "run", "-d",
            "--name", &name,
            "--network", first_network,
            "--env", "AUTO_APPROVE_USERS=true",
            "--publish", "127.0.0.1::8080",
            ALPINE_IMAGE,
            "sleep", "300",
        ]);
        assert!(
            out.status.success(),
            "docker run rendezvous failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let guard = ContainerGuard::new(name.clone());

        // Resolve the host-side port that Docker mapped to container:8080.
        let port_out = docker(&["port", &name, "8080"]);
        assert!(port_out.status.success(), "docker port {} 8080 failed", name);
        let port_str = String::from_utf8_lossy(&port_out.stdout);
        let host_port = port_str.trim().split(':').last()
            .unwrap_or_else(|| panic!("could not parse host port from: {:?}", port_str));
        let host_url = format!("http://127.0.0.1:{}", host_port);

        // Copy binary in.
        let src = binary.to_str().expect("non-UTF8 rendezvous path");
        let dst = format!("{}:/usr/local/bin/rendezvous", name);
        let cp = docker(&["cp", src, &dst]);
        assert!(cp.status.success(), "docker cp rendezvous binary failed");

        // Make executable and start it in background.
        let exec = docker_exec(
            &name,
            "chmod +x /usr/local/bin/rendezvous && /usr/local/bin/rendezvous &",
        );
        assert!(exec.status.success(), "failed to start rendezvous binary");

        // Attach to extra networks.
        for net in extra_networks {
            let out = docker(&["network", "connect", net, &name]);
            assert!(
                out.status.success(),
                "docker network connect {} {} failed:\n{}",
                net,
                name,
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Health-check: poll GET /peers?username=healthcheck until 200 or timeout.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let probe = docker_exec(
                &name,
                "wget -qO- 'http://127.0.0.1:8080/peers?username=healthcheck' 2>/dev/null",
            );
            if probe.status.success() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "rendezvous container {} did not become healthy in 10 s",
                    name
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        RendezvousContainer { container: guard, name, host_url }
    }

    /// Start a rendezvous container from a **pre-built Docker image** instead
    /// of copying in a compiled binary.  Used when `RENDEZVOUS_IMAGE` is set
    /// (e.g. `rendezvous-py:latest` for the Python implementation CI job).
    ///
    /// The image must serve the same REST API on port 8080 and must include
    /// `wget` so the shared health-check and `wait_for_peers` helpers work.
    /// Waits up to 30 s for the server to become healthy (Python/Django startup
    /// is slower than the compiled Rust binary).
    pub fn start_from_image(
        image: &str,
        first_network: &str,
        extra_networks: &[&str],
    ) -> Self {
        let sfx = unique_suffix();
        let name = format!("rendezvous-{}", sfx);

        let out = docker(&[
            "run", "-d",
            "--name", &name,
            "--network", first_network,
            "--env", "AUTO_APPROVE_USERS=true",
            "--publish", "127.0.0.1::8080",
            image,
        ]);
        assert!(
            out.status.success(),
            "docker run {} failed:\n{}",
            image,
            String::from_utf8_lossy(&out.stderr)
        );
        let guard = ContainerGuard::new(name.clone());

        let port_out = docker(&["port", &name, "8080"]);
        assert!(port_out.status.success(), "docker port {} 8080 failed", name);
        let port_str = String::from_utf8_lossy(&port_out.stdout);
        let host_port = port_str.trim().split(':').last()
            .unwrap_or_else(|| panic!("could not parse host port from: {:?}", port_str));
        let host_url = format!("http://127.0.0.1:{}", host_port);

        // Attach to extra networks.
        for net in extra_networks {
            let out = docker(&["network", "connect", net, &name]);
            assert!(
                out.status.success(),
                "docker network connect {} {} failed:\n{}",
                net,
                name,
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Health-check: Django startup takes longer — allow 30 s.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let probe = docker_exec(
                &name,
                "wget -qO- 'http://127.0.0.1:8080/peers?username=healthcheck' 2>/dev/null",
            );
            if probe.status.success() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "rendezvous container {} ({}) did not become healthy in 30 s",
                    name, image
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        RendezvousContainer { container: guard, name, host_url }
    }
}

/// Start the rendezvous server for integration tests.
///
/// If `RENDEZVOUS_IMAGE` is set in the environment the server is started from
/// that pre-built Docker image (e.g. `rendezvous-py:latest`).  Otherwise the
/// compiled Rust binary from `build` is used (default / Rust CI job).
pub fn start_rendezvous(build: &Build, first_network: &str, extra_networks: &[&str]) -> RendezvousContainer {
    if let Ok(image) = std::env::var("RENDEZVOUS_IMAGE") {
        RendezvousContainer::start_from_image(&image, first_network, extra_networks)
    } else {
        RendezvousContainer::start(&build.rendezvous, first_network, extra_networks)
    }
}

// ---------------------------------------------------------------------------
// Copy a binary into a container and set it executable
// ---------------------------------------------------------------------------

pub fn copy_binary_to_container(binary: &PathBuf, container: &str, dest: &str) {
    let src = binary.to_str().expect("non-UTF8 binary path");
    let target = format!("{}:{}", container, dest);
    let cp = docker(&["cp", src, &target]);
    assert!(
        cp.status.success(),
        "docker cp {} -> {} failed:\n{}",
        src,
        target,
        String::from_utf8_lossy(&cp.stderr)
    );
    let chmod = docker_exec(container, &format!("chmod +x {}", dest));
    assert!(chmod.status.success(), "chmod +x {} in {} failed", dest, container);
}

// ---------------------------------------------------------------------------
// wait_for_file — poll until a path appears inside a container
// ---------------------------------------------------------------------------

/// Poll the rendezvous `/peers?username=<username>` endpoint (via wget inside
/// `container`) until at least `min_peers` are registered, or `timeout` elapses.
/// Returns `true` if the peer count was reached in time.
pub fn wait_for_peers(
    container: &str,
    min_peers: usize,
    username: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let out = docker_exec(
            container,
            &format!(
                "wget -qO- 'http://127.0.0.1:8080/peers?username={}' 2>/dev/null",
                username
            ),
        );
        if out.status.success() {
            let body = String::from_utf8_lossy(&out.stdout);
            // Count occurrences of "node_id" as a proxy for peer count.
            let count = body.matches("node_id").count();
            if count >= min_peers {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Poll `docker exec <container> test -f <path>` until the file exists or
/// `timeout` elapses.  Returns `true` if the file appeared.
pub fn wait_for_file(container: &str, path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let out = docker_exec(container, &format!("test -f {}", path));
        if out.status.success() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Read the content of a file inside a container. Panics if the exec fails.
pub fn read_file_in_container(container: &str, path: &str) -> String {
    let out = docker_exec(container, &format!("cat {}", path));
    assert!(
        out.status.success(),
        "cat {} in {} failed:\n{}",
        path,
        container,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Sign up a test account on the rendezvous server, obtain a Bearer token,
/// and write it to `/root/dddatasync/.token` in each of `token_containers`.
///
/// The rendezvous container must have been started with `AUTO_APPROVE_USERS=true`
/// and with a host-published port (see `RendezvousContainer::start`).
/// `POST /register` requires a valid Bearer token, so this must be called
/// before `dddatasync start` runs.
///
/// `dddatasync login` is still run after this to set up the iroh identity.
/// Its server-auth step will fail (device passphrase ≠ server password) and
/// warn, but the failure path does not overwrite the token file — so the
/// pre-injected token survives intact.
pub fn rendezvous_signup_and_save_token(
    rendezvous: &RendezvousContainer,
    token_containers: &[&str],
    username: &str,
    password: &str,
) {
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");

    // Wait until the rendezvous is reachable from the host via the published
    // port.  The container-internal health check (docker_exec wget) can pass
    // slightly before Docker's iptables rules are ready on the host side.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ok = http
            .get(&format!("{}/peers?username=healthcheck", rendezvous.host_url))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ok { break; }
        assert!(
            Instant::now() < deadline,
            "rendezvous not reachable from host at {} after 15 s",
            rendezvous.host_url
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Signup — ignore failures (e.g. 409 if the account already exists).
    let _ = http
        .post(&format!("{}/auth/signup", rendezvous.host_url))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({
            "username": username,
            "email": format!("{}@dddatasync.local", username),
            "password": password,
        }).to_string())
        .send();

    // Login and extract the Bearer token.  Use .text() so the raw body is
    // available in the error message if JSON parsing fails.
    let body = http
        .post(&format!("{}/auth/login", rendezvous.host_url))
        .header("Content-Type", "application/json")
        .body(serde_json::json!({"username": username, "password": password}).to_string())
        .send()
        .unwrap_or_else(|e| panic!("POST /auth/login failed: {}", e))
        .text()
        .unwrap_or_else(|e| panic!("failed to read login response body: {}", e));

    let resp: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("login response is not JSON: {} | body: {:?}", e, body));

    let token = resp["token"]
        .as_str()
        .unwrap_or_else(|| panic!("no token in login response: {:?}", resp));

    // Inject the token file into each dddatasync container.
    for &container in token_containers {
        docker_exec(
            container,
            &format!(
                "mkdir -p /root/dddatasync && \
                 printf '%s' '{}' > /root/dddatasync/.token && \
                 chmod 600 /root/dddatasync/.token",
                token
            ),
        );
    }
}
