# Run all CI jobs locally via act (https://github.com/nektos/act).
#
# Secrets: create a .secrets file (gitignored) with one KEY=VALUE per line:
#   IROH_SERVICES_API_SECRET=your_key_here
#
# The workflow forwards IROH_SERVICES_API_SECRET to all jobs automatically.
# To add the secret on GitHub: Settings → Secrets and variables → Actions.
act-test:
    act --container-architecture linux/amd64 \
        -P ubuntu-latest=catthehacker/ubuntu:act-latest \
        --secret-file .secrets

# Standard workspace build (dev profile, full debug info).
build:
    cargo build --workspace

# Faster build: line-tables-only debug info (enough for backtraces, much
# smaller .d files → faster linking). Uses target/fast/ so it never
# invalidates the regular dev cache.
#
# One-time Mac speedup: add your terminal app as a Developer Tool in
# System Settings → Privacy & Security → Developer Tools. This disables
# XProtect scanning of every compiled binary — can roughly halve build times
# for projects with many small binaries (build scripts, test harnesses, etc.).
# See https://nnethercote.github.io/2025/09/04/faster-rust-builds-on-mac.html
build-fast:
    cargo build --workspace --profile fast

# Fastest build: no debug info at all. Cold builds are as fast as they get;
# the trade-off is no backtraces or debugger symbols. Uses target/faster/.
#
# Nightly bonus: add RUSTFLAGS="-Zhint-mostly-unused" to surface crates where
# only a small fraction of features are used (e.g. tokio = "full"), which can
# yield significant compile-time wins after trimming feature flags.
# See https://nnethercote.github.io/2025/12/05/how-to-speed-up-the-rust-compiler-in-december-2025.html
build-faster:
    cargo build --workspace --profile faster
