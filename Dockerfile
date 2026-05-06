# ─── Stage 0: Valkey binary source ───────────────────────────────────────────
# Pull the official Valkey image just to extract the server binary.
# Used in the runtime stage for `backend = "embedded"` mode.
# Using the same tag as docker-compose.valkey-cluster.yml for consistency.
FROM docker.io/valkey/valkey:8-alpine AS valkey-source

# ─── Stage 1: Frontend Builder ───────────────────────────────────────────────
# Builds the Vue 3 admin panel (web/admin-ui).
# Output dist/ is embedded into the Rust binary via `rust_embed` in
# crates/waf-api/src/static_files.rs and served at /ui/* by prx-waf itself.
FROM node:22-slim AS frontend-builder

WORKDIR /ui

COPY web/admin-panel/package.json web/admin-panel/package-lock.json* ./
RUN npm ci --ignore-scripts

COPY web/admin-panel/ ./
RUN npm run build

# ─── Stage 2: Rust Builder ────────────────────────────────────────────────────
FROM rust:1.91-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/prx-waf/Cargo.toml    crates/prx-waf/Cargo.toml
COPY crates/gateway/Cargo.toml    crates/gateway/Cargo.toml
COPY crates/waf-engine/Cargo.toml crates/waf-engine/Cargo.toml
COPY crates/waf-storage/Cargo.toml crates/waf-storage/Cargo.toml
COPY crates/waf-api/Cargo.toml    crates/waf-api/Cargo.toml
COPY crates/waf-common/Cargo.toml crates/waf-common/Cargo.toml

# Create stub source files to pre-build dependencies
RUN mkdir -p crates/prx-waf/src && echo 'fn main(){}' > crates/prx-waf/src/main.rs && \
    mkdir -p crates/gateway/src   && echo 'pub fn dummy(){}' > crates/gateway/src/lib.rs && \
    mkdir -p crates/waf-engine/src && echo 'pub fn dummy(){}' > crates/waf-engine/src/lib.rs && \
    mkdir -p crates/waf-storage/src && echo 'pub fn dummy(){}' > crates/waf-storage/src/lib.rs && \
    mkdir -p crates/waf-api/src   && echo 'pub fn dummy(){}' > crates/waf-api/src/lib.rs && \
    mkdir -p crates/waf-common/src && echo 'pub fn dummy(){}' > crates/waf-common/src/lib.rs

# Pre-build all dependencies (layer-cache friendly) — with valkey feature enabled
RUN cargo build --release --features gateway/valkey 2>/dev/null || true

# Now copy the real source tree
COPY . .

# Overwrite the local dist with the freshly built frontend (RustEmbed embeds at compile time)
COPY --from=frontend-builder /ui/dist ./web/admin-panel/dist/

# Rebuild with real source (only changed crates will be recompiled)
RUN cargo build --release --features gateway/valkey -p prx-waf

# ─── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Runtime dependencies
#   - ca-certificates / libssl3: TLS for upstreams + GitHub release downloads
#   - curl:                      container HEALTHCHECK probe (HTTP /health)
#   - tar:                       VictoriaLogs installer extracts the upstream tar.gz
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Copy WAF binary
COPY --from=builder /build/target/release/prx-waf /usr/local/bin/prx-waf

# Copy the Valkey server binary for embedded mode (backend = "embedded").
# EmbeddedValkey finds it at /usr/local/bin/valkey-server via PATH when
# binary_path is empty in [cache.embedded].
# If you only use [cache] backend = "memory" or external Valkey and never
# "embedded", you may omit the valkey-source stage and this COPY to shrink the image.
COPY --from=valkey-source /usr/local/bin/valkey-server /usr/local/bin/valkey-server

# Copy default config, OWASP rules, and frontend dist
COPY configs/   /app/configs/
COPY rules/     /app/rules/
COPY --from=frontend-builder /ui/dist /app/web/admin-panel/dist

RUN chmod +x /usr/local/bin/prx-waf

EXPOSE 80 443 9527

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9527/health || exit 1

CMD ["/usr/local/bin/prx-waf", "--config", "/app/configs/default.toml", "run"]
