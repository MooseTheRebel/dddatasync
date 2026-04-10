# ── Build stage ─────────────────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /build

# Copy the full workspace so Cargo can resolve all members.
# Build context must be the repository root (see compose.yml).
COPY Cargo.toml Cargo.lock ./
COPY src/         ./src/
COPY tests/       ./tests/
COPY rendezvous/  ./rendezvous/

RUN cargo build --release -p rendezvous

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rendezvous /usr/local/bin/rendezvous

EXPOSE 8080

ENV RUST_LOG=rendezvous=info

ENTRYPOINT ["/usr/local/bin/rendezvous"]
