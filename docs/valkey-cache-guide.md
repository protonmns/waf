# Valkey Cache — Configuration & Deployment Guide

> **Feature:** FR-009 Smart Caching — Valkey integration  
> **Backends:** `memory` · `embedded` · `standalone` · `cluster`

---

## 1. Overview

PRX-WAF supports four cache backends selectable via `configs/default.toml`:

| Backend | Description | Extra process | Best for |
|---|---|---|---|
| `memory` | In-process Moka LRU (default) | None | Single node, low traffic |
| `embedded` | `valkey-server` spawned as child process via UNIX socket | Automatic | Single node, needs persistence resistance |
| `standalone` | External Valkey/Redis server over TCP | Manual | Dedicated cache server |
| `cluster` | Valkey cluster, topology auto-discovered | Manual (3+ nodes) | High-availability, horizontal scale |

The `embedded`, `standalone`, and `cluster` backends require the binary to be compiled with the `valkey` Cargo feature (already enabled in the Dockerfile).

---

## 2. Configuration (`configs/default.toml`)

### 2.1 In-memory (default — no changes required)

```toml
[cache]
enabled        = true
max_size_mb    = 256
default_ttl_secs = 60
max_ttl_secs   = 3600
backend        = "memory"
```

No additional sections needed.

---

### 2.2 Embedded Valkey

Spawns `valkey-server` as a child process bound to a UNIX socket. The child is killed automatically when the WAF exits — no orphan processes.

**Binary search order:**

1. `cache.embedded.binary_path` (explicit path in config)
2. `valkey-server` on `$PATH`
3. `redis-server` on `$PATH` (protocol-compatible fallback)

```toml
[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
backend          = "embedded"

[cache.embedded]
binary_path = ""              # leave empty to auto-detect
data_dir    = "/tmp/prx-valkey"
extra_args  = []              # additional valkey-server CLI flags
```

**UNIX socket** is auto-generated at `/tmp/prx-valkey-{pid}.sock`. The WAF waits up to 5 seconds for the socket to become ready before accepting traffic.

**Maxmemory** is set to `max_size_mb` (the same limit as the Moka LRU) with the `allkeys-lru` eviction policy.

---

### 2.3 Standalone Valkey / Redis

Connect to an existing external Valkey or Redis instance over TCP (optionally TLS).

```toml
[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
backend          = "standalone"

[cache.valkey]
seeds                      = ["127.0.0.1:6379"]
password                   = ""          # leave empty if no auth
db                         = 0
tls                        = false
# tls_ca_cert              = "/etc/prx-waf/tls/ca.pem"  # required when tls=true
pool_size                  = 4
connect_timeout_ms         = 2000
command_timeout_ms         = 500
circuit_breaker_threshold  = 5           # consecutive failures → open circuit
circuit_breaker_reset_secs = 30          # seconds before half-open retry
fallback_to_memory         = true        # degrade gracefully on failure
```

> **Circuit breaker** — after `circuit_breaker_threshold` consecutive errors the
> breaker opens: all cache operations fall through to the in-memory fallback.
> After `circuit_breaker_reset_secs` it enters half-open state and retries once.

---

### 2.4 Valkey Cluster

Auto-discovers the full topology from the seed nodes. Only provide 1–3 seeds; the client queries `CLUSTER SLOTS` and connects to all masters.

```toml
[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
backend          = "cluster"

[cache.valkey]
seeds                      = ["10.0.1.1:6379", "10.0.1.2:6379", "10.0.1.3:6379"]
password                   = ""
tls                        = true
tls_ca_cert                = "/etc/prx-waf/tls/valkey-ca.pem"
pool_size                  = 4
connect_timeout_ms         = 2000
command_timeout_ms         = 500
circuit_breaker_threshold  = 5
circuit_breaker_reset_secs = 30
fallback_to_memory         = true
```

---

## 3. Deployment

### 3.1 Standard Docker Compose (memory or embedded backend)

```bash
# Default: memory backend
podman-compose up -d --build

# Switch to embedded Valkey at startup
CACHE_BACKEND=embedded podman-compose up -d --build
```

The `CACHE_BACKEND` environment variable overrides `[cache] backend` in the config at startup. Valid values: `memory`, `embedded`, `standalone`, `cluster`.

```yaml
# docker-compose.yml excerpt
environment:
  CACHE_BACKEND: ${CACHE_BACKEND:-memory}
```

---

### 3.2 Valkey Cluster mode (`docker-compose.valkey-cluster.yml`)

A ready-to-use 3-node Valkey cluster + WAF + PostgreSQL:

```bash
# Start full cluster stack
docker compose -f docker-compose.valkey-cluster.yml up -d

# Wait for the one-shot cluster initialiser to finish
docker compose -f docker-compose.valkey-cluster.yml logs -f valkey-init

# Verify WAF sees the cluster
curl http://localhost:16827/api/cache/backend
```

**Service layout:**

| Service | Image | Ports | Role |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | — | DB |
| `valkey-1` | `valkey/valkey:8-alpine` | `16381:6379` | Cluster node 1 |
| `valkey-2` | `valkey/valkey:8-alpine` | `16382:6379` | Cluster node 2 |
| `valkey-3` | `valkey/valkey:8-alpine` | `16383:6379` | Cluster node 3 |
| `valkey-init` | `valkey/valkey:8-alpine` | — | One-shot cluster creator |
| `prx-waf` | `./Dockerfile` | `16880/16843/16827` | WAF + Admin UI |

The `valkey-init` container runs `valkey-cli --cluster create` with `--cluster-replicas 0` then exits. The WAF depends on `valkey-init` completing successfully before starting.

**To scale nodes or add replicas**, add more `valkey-N` services and update the seed addresses in `docker-compose.valkey-cluster.yml` and `configs/default.toml`.

---

### 3.3 Production bare-metal / Kubernetes

**Step 1 — Build with the `valkey` feature:**

```bash
cargo build --release --features gateway/valkey -p prx-waf
```

**Step 2 — Install `valkey-server` (embedded mode only):**

```bash
# Debian/Ubuntu
apt-get install -y valkey          # or: install the binary from valkey/valkey releases
ln -sf /usr/bin/valkey-server /usr/local/bin/valkey-server

# Or set binary_path explicitly in config
```

**Step 3 — Configure `configs/default.toml`** with the chosen backend section.

**Step 4 — Set env var (optional override):**

```bash
export CACHE_BACKEND=embedded   # or standalone / cluster
./prx-waf --config configs/default.toml
```

---

## 4. Cache Rule Configuration (`rules/cache.yaml`)

Per-route TTL overrides. Hot-reloaded on file change (no restart needed).

```yaml
# rules/cache.yaml
rules:
  - route_id: "api-public"
    ttl_seconds: 300        # cache public API responses for 5 min

  - route_id: "static-assets"
    ttl_seconds: 3600       # 1 hour for static files

  - route_id: "auth-protected"
    ttl_seconds: 0          # 0 = opt-out of caching entirely
```

> Routes without a rule use `default_ttl_secs` from `[cache]` config.  
> `ttl_seconds: 0` triggers a `bypassed_explicit_deny` audit counter.

---

## 5. Monitoring

### 5.1 Admin UI — Cache Dashboard

Navigate to **Admin Panel → Cache** (`/cache`):

| Widget | Data source | Refresh |
|---|---|---|
| Hit Ratio KPI | `/api/cache/stats` | 5 s |
| Entry Count KPI | `/api/cache/stats` | 5 s |
| Memory Used KPI | `/api/cache/stats` | 5 s |
| Ops/sec KPI | `/api/cache/stats` | 5 s |
| Hit/Miss timeline chart | `/api/cache/stats/timeseries?minutes=60` | 60 s |
| Top routes table | `/api/cache/routes/top?limit=20` | 30 s |
| Backend info card | `/api/cache/backend` | 15 s |

The dashboard also exposes **Purge by tag**, **Purge by route**, and **Flush all** actions.

### 5.2 REST API endpoints

```bash
# Overall stats
curl http://localhost:16827/api/cache/stats

# Backend identity & health
curl http://localhost:16827/api/cache/backend

# Per-minute hit/miss timeseries (last 60 min)
curl "http://localhost:16827/api/cache/stats/timeseries?minutes=60"

# Top routes by hit count
curl "http://localhost:16827/api/cache/routes/top?limit=20"

# Purge entries tagged with a specific tag
curl -X POST http://localhost:16827/api/cache/purge/tag \
     -H "Content-Type: application/json" \
     -d '{"tag": "catalog"}'

# Purge all entries for a route rule
curl -X POST http://localhost:16827/api/cache/purge/route \
     -H "Content-Type: application/json" \
     -d '{"route_id": "api-public"}'

# Flush entire cache
curl -X DELETE http://localhost:16827/api/cache
```

---

## 6. Behaviour Reference

### Circuit Breaker States

```
         ┌──────────────────┐
  error  │                  │  success × threshold
────────▶│     CLOSED       │◀──────────────────────┐
         │  (serving cache) │                        │
         └──────────────────┘                        │
               │ failures ≥ threshold                │
               ▼                                     │
         ┌──────────────────┐             ┌──────────────────┐
         │      OPEN        │  timeout   │   HALF-OPEN      │
         │ (fallback memory)│───────────▶│  (probe 1 req)   │
         └──────────────────┘            └──────────────────┘
```

When `fallback_to_memory = true` (default), the WAF never rejects cached reads — it silently falls back to the in-process Moka LRU while Valkey is degraded.

### Embedded Valkey startup flags

```
valkey-server
  --unixsocket     /tmp/prx-valkey-{pid}.sock
  --unixsocketperm 700
  --bind           127.0.0.1
  --port           0                # TCP disabled; UNIX socket only
  --save           ""               # no persistence
  --maxmemory      {max_size_mb}mb
  --maxmemory-policy allkeys-lru
  --loglevel       warning
  --protected-mode no
```

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `valkey-server not found in PATH` | Binary missing | Install Valkey or set `cache.embedded.binary_path` |
| `embedded Valkey did not become ready within 5s` | Permission or resource issue | Check `/tmp` write access; check logs with `RUST_LOG=debug` |
| Circuit breaker stays OPEN | Valkey unreachable | Check network, firewall, seeds config |
| `W.some is not a function` in dashboard | Old frontend build | Run `npm run build` in `web/admin-panel` and redeploy |
| High memory fragmentation | Long-running instance | Set `--maxmemory-policy allkeys-lru` (already default) |
| Cache dashboard shows all `—` | WAF not yet reached the API endpoint | Wait for first request to be proxied; `/api/cache/stats` starts at zero |

### Useful debug commands

```bash
# Live log stream (embedded mode)
RUST_LOG=gateway=debug ./prx-waf 2>&1 | grep -i valkey

# Inspect embedded socket from the host
valkey-cli -s /tmp/prx-valkey-$(pgrep prx-waf).sock INFO server

# Check cluster topology
valkey-cli -h 127.0.0.1 -p 16381 CLUSTER NODES
```
