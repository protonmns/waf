# Implementation Plan: Valkey Cache Integration + Cache Dashboard

> **Scope:** Tích hợp Valkey làm distributed cache backend bên cạnh moka in-memory,
> hỗ trợ 2 deployment mode (embedded single-binary + external cluster), và xây mới
> dashboard `/admin-panel/dashboards/cache` trên Vue 3 admin UI.

---

## 0. Tổng quan kiến trúc sau khi hoàn thành

```
┌─────────────────── PRX-WAF Process ───────────────────────────────┐
│                                                                     │
│  Request Path                                                       │
│  ─────────────────────────────────────────────────────────────     │
│  [TierGate]→[MethodGate]→[AuthGate]→[RouteRuleGate]               │
│           ↓                                                         │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              CacheStore (trait object)                    │      │
│  │  ┌──────────────────┐    ┌───────────────────────────┐   │      │
│  │  │  MokaStore       │    │  ValkeyStore              │   │      │
│  │  │  (in-process     │    │  (async redis-compat      │   │      │
│  │  │   LRU, always    │    │   client via fred crate)  │   │      │
│  │  │   available)     │    │                           │   │      │
│  │  └──────────────────┘    └───────────────────────────┘   │      │
│  │               ↑ selected by [cache.backend] config        │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│  Embedded Valkey (optional, tokio::process child)                  │
│  ─────────────────────────────────────────────────────────────     │
│  valkey-server --port 6379 --bind 127.0.0.1 --save ""             │
│  (lifecycle tied to parent process via Supervisor struct)           │
│                                                                     │
└─────────────────────────────────────────────────────────────────── ┘

External Cluster mode:
  prx-waf → TCP/TLS → [Valkey Cluster nodes]
                         node-1 master
                         node-2 master
                         node-3 master
                         (replica set optional)
```

---

## 1. Phases tổng thể

| Phase | Nội dung | Effort | Phụ thuộc |
|-------|----------|--------|-----------|
| **P1** | Abstraction layer `CacheBackend` trait | 1 ngày | — |
| **P2** | `ValkeyStore` implementation (fred crate) | 2 ngày | P1 |
| **P3** | Embedded Valkey binary supervisor | 1.5 ngày | P2 |
| **P4** | Cluster mode config + topology discovery | 1 ngày | P2 |
| **P5** | Config schema + hot-reload | 0.5 ngày | P3, P4 |
| **P6** | New API endpoints cho dashboard | 1 ngày | P2 |
| **P7** | Vue 3 Cache Dashboard | 2 ngày | P6 |
| **P8** | Tests + E2E | 1.5 ngày | P1–P7 |

**Tổng: ~10.5 dev-days**

---

## Phase 1 — `CacheBackend` Trait Abstraction

### Mục tiêu
Tách `ResponseCache` khỏi implementation cụ thể (moka). Cả Moka và Valkey đều impl cùng 1 trait, `ResponseCache` dùng `Box<dyn CacheBackend>`.

### File mới/sửa

**`crates/gateway/src/cache/backend.rs`** — trait definition

```rust
use async_trait::async_trait;
use bytes::Bytes;

use super::store::CachedResponse;
use super::stats::CacheStatsSnapshot;

/// Unified interface over every cache storage implementation.
/// Methods are async and infallible — implementors must handle
/// their own errors internally and degrade gracefully.
#[async_trait]
pub trait CacheBackend: Send + Sync + 'static {
    /// Fetch a cached entry. Returns `None` on miss or error.
    async fn get(&self, key: &str) -> Option<CachedResponse>;

    /// Store an entry. Returns `true` if the entry was stored.
    async fn put(&self, key: &str, value: CachedResponse, ttl_secs: u64) -> bool;

    /// Remove a single key. Returns count removed (0 or 1).
    async fn remove(&self, key: &str) -> usize;

    /// Remove all keys matching the tag (via reverse index or SCAN pattern).
    async fn purge_by_tag(&self, tag: &str) -> usize;

    /// Remove all keys belonging to a route rule id.
    async fn purge_by_route_id(&self, route_id: &str) -> usize;

    /// Remove all keys whose cache-key contains `host`.
    async fn purge_host(&self, host: &str) -> usize;

    /// Flush entire cache.
    async fn flush(&self);

    /// Snapshot of hit/miss/eviction counters.
    fn stats(&self) -> CacheStatsSnapshot;

    /// Current in-store entry count (approximate for distributed stores).
    fn entry_count(&self) -> u64;

    /// Tag index size (distinct tag→key mappings tracked locally).
    fn tag_index_size(&self) -> usize;

    /// Backend health — used by dashboard and circuit-breaker.
    async fn ping(&self) -> BackendHealth;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendHealth {
    pub ok: bool,
    pub latency_us: u64,
    pub error: Option<String>,
}
```

**`crates/gateway/src/cache/moka_store.rs`** — refactor hiện tại `store.rs` sang impl `CacheBackend`

Không thay đổi logic, chỉ wrap `ResponseCache` hiện tại thành `MokaStore` và implement trait. Toàn bộ test hiện tại giữ nguyên.

**`crates/gateway/src/cache/store.rs`** — giữ nguyên public API, delegate xuống `Box<dyn CacheBackend>`

```rust
pub struct ResponseCache {
    backend: Arc<dyn CacheBackend>,
    // Giữ resolver + rule_set như cũ — gate pipeline không đổi
    resolver: CachePolicyResolver,
    tag_index: Arc<TagIndex>,  // local index vẫn cần cho Moka
}
```

---

## Phase 2 — `ValkeyStore` Implementation

### Crate dependency

Dùng **`fred`** (async Redis/Valkey client, Rust-native, hỗ trợ cluster mode, TLS, connection pooling):

```toml
# crates/gateway/Cargo.toml
fred = { version = "9", features = ["cluster-discovery", "sentinel", "tls-rustls", "monitor"] }
serde_json = "1"
```

### File mới: `crates/gateway/src/cache/valkey_store.rs`

#### 2.1 Serialization

`CachedResponse` serialize sang `JSON` trước khi push vào Valkey. Key format giữ nguyên:  
`prx:cache:{method}:{host}:{path}?{query}`

Tag index dùng Valkey Sets:  
`prx:tag:{tag_name}` → `SMEMBERS` → list of cache keys  
`prx:key_tags:{cache_key}` → `SMEMBERS` → list of tags (reverse index để clean up khi del key)

```rust
const KEY_PREFIX: &str = "prx:cache:";
const TAG_PREFIX: &str = "prx:tag:";
const KEY_TAGS_PREFIX: &str = "prx:key_tags:";
```

#### 2.2 Core methods

```rust
impl ValkeyStore {
    pub async fn new(cfg: &ValkeyConfig) -> Result<Self, ValkeyError> { ... }

    async fn vk_key(key: &str) -> String {
        format!("{KEY_PREFIX}{key}")
    }

    // get: GET → deserialize JSON → CachedResponse
    // put: SET EX ttl_secs + SADD tags + SADD key_tags (pipeline)
    // remove: DEL key + cleanup tag sets via SREM
    // purge_by_tag: SMEMBERS prx:tag:{tag} → batch DEL
    // flush: SCAN 0 MATCH prx:cache:* → batch DEL (non-blocking)
    // ping: PING + measure latency
}
```

#### 2.3 Circuit-breaker wrapper

Valkey lỗi không được làm crash request path. Bọc bên ngoài:

```rust
pub struct CircuitBreakerStore {
    inner: Arc<ValkeyStore>,
    fallback: Arc<MokaStore>,      // fallback = local moka
    state: Arc<AtomicCircuitState>,
    // half-open probe mỗi 10s
}
```

Khi Valkey unreachable → tự động fallback về MokaStore và emit metric `valkey_circuit_open=true`.

---

## Phase 3 — Embedded Valkey Binary Supervisor

### Mục tiêu
`mode = "embedded"` → prx-waf tự spawn `valkey-server` process con, quản lý lifecycle, không cần deploy riêng.

### File mới: `crates/gateway/src/cache/embedded_valkey.rs`

```rust
pub struct EmbeddedValkey {
    child: tokio::process::Child,
    socket_path: PathBuf,   // UNIX socket: /tmp/prx-valkey-{pid}.sock
    data_dir: PathBuf,
}

impl EmbeddedValkey {
    /// Spawn valkey-server child process.
    /// Tìm binary theo thứ tự:
    ///   1. [cache.embedded.binary_path] trong config
    ///   2. PATH lookup: `which valkey-server`
    ///   3. Fallback: `redis-server` (valkey là redis-compatible)
    pub async fn spawn(cfg: &EmbeddedValkeyConfig) -> Result<Self> {
        let args = build_args(cfg); // --unixsocket, --maxmemory, --save ""
        let child = Command::new(&binary)
            .args(&args)
            .kill_on_drop(true)   // tự kill khi process cha chết
            .spawn()?;
        
        // Wait for ready: poll PING qua socket tối đa 5s
        Self::wait_ready(&socket_path, Duration::from_secs(5)).await?;
        Ok(...)
    }
}

impl Drop for EmbeddedValkey {
    fn drop(&mut self) {
        // SHUTDOWN NOSAVE → graceful shutdown
        let _ = self.child.start_kill();
    }
}
```

**Valkey startup args cho embedded mode:**

```
valkey-server
  --unixsocket /tmp/prx-valkey-{pid}.sock
  --unixsocketperm 700
  --bind 127.0.0.1
  --port 0                    # disable TCP khi dùng socket
  --save ""                   # no persistence (in-memory only)
  --maxmemory {max_size_mb}mb
  --maxmemory-policy allkeys-lru
  --loglevel warning
  --protected-mode no
```

---

## Phase 4 — Cluster Mode Config

Cluster mode: kết nối tới Valkey Cluster bên ngoài qua fred's cluster client.

```toml
[cache.valkey]
mode = "cluster"
# seeds — ít nhất 1 seed node; fred tự discover phần còn lại
seeds = ["10.0.1.1:6379", "10.0.1.2:6379", "10.0.1.3:6379"]
# TLS (optional)
tls = false
# tls_ca_cert  = "/etc/prx-waf/tls/valkey-ca.pem"
# tls_client_cert = "/etc/prx-waf/tls/valkey-client.pem"
# tls_client_key  = "/etc/prx-waf/tls/valkey-client.key"
# Connection pool per node
pool_size = 4
connect_timeout_ms = 2000
command_timeout_ms = 500
# Circuit-breaker: trip after N consecutive failures
circuit_breaker_threshold = 5
circuit_breaker_reset_secs = 30
```

Fred cluster client tự động:
- Discover topology qua `CLUSTER SLOTS`/`CLUSTER SHARDS`
- Route keys tới đúng shard (hash slot)
- Retry khi node failover
- Re-discover khi `MOVED`/`ASK` redirect

---

## Phase 5 — Config Schema (TOML) + Hot-reload

### Full `[cache]` section sau khi implement

```toml
# ── Phase 5: Response Caching ─────────────────────────────────────────────────
[cache]
enabled = true
max_size_mb = 256            # dùng cho moka (local) hoặc maxmemory cho embedded valkey
default_ttl_secs = 60
max_ttl_secs = 3600
rules_path = "rules/cache.yaml"

# Cache backend selector
# Values: "memory" (default, moka) | "embedded" | "standalone" | "cluster"
backend = "memory"

# ── Valkey: Embedded mode ─────────────────────────────────────────────────────
# Chỉ đọc khi backend = "embedded"
[cache.embedded]
# Path tới valkey-server binary. Để trống = auto-detect từ PATH.
binary_path = ""
# Working directory cho data files (nếu persistence được bật).
data_dir = "/tmp/prx-valkey"
# Pass-through args bổ sung (advanced users).
extra_args = []

# ── Valkey: Standalone / Cluster ──────────────────────────────────────────────
# Đọc khi backend = "standalone" hoặc "cluster"
[cache.valkey]
# mode = "standalone" | "cluster"
mode = "standalone"
# Standalone: chỉ phần tử đầu tiên được dùng
# Cluster:    ít nhất 1 seed (fred discovers the rest)
seeds = ["127.0.0.1:6379"]
password = ""                # Redis AUTH / Valkey requirepass
db = 0                       # Logical DB (standalone only; cluster luôn db=0)
tls = false
pool_size = 4
connect_timeout_ms = 2000
command_timeout_ms = 500
circuit_breaker_threshold = 5
circuit_breaker_reset_secs = 30
# Khi circuit open, dùng local moka làm fallback
fallback_to_memory = true
```

### Hot-reload

Config Valkey **không** hot-reload vì reconnect là operation nặng. Thay đổi backend yêu cầu restart.  
`rules_path` (cache.yaml) vẫn hot-reload như hiện tại (CacheRuleWatcher + notify, 200ms debounce).

---

## Phase 6 — New API Endpoints cho Dashboard

Thêm vào `crates/waf-api/src/cache_api.rs` và đăng ký trong `server.rs`:

### 6.1 Backend info

```
GET /api/cache/backend
```

Response:
```json
{
  "backend": "embedded",
  "valkey_version": "7.2.4",
  "mode": "embedded",
  "connected": true,
  "nodes": [
    { "addr": "127.0.0.1:6379", "role": "master", "slots": "0-16383" }
  ],
  "memory_used_bytes": 12582912,
  "memory_max_bytes": 268435456,
  "keyspace": { "db0": { "keys": 1842, "expires": 1201 } },
  "health": { "ok": true, "latency_us": 142 },
  "circuit_breaker": "closed"
}
```

### 6.2 Extended stats (bổ sung vào `/api/cache/stats`)

```json
{
  // Hiện có
  "hits": 98421,
  "misses": 3211,
  "evictions": 421,
  "stores": 3890,
  "entry_count": 1842,
  "bypassed_critical": 5012,
  "bypassed_authenticated": 8711,
  "bypassed_explicit_deny": 2100,
  "purges_tag": 500,
  "purges_route": 120,
  "tag_index_size": 312,

  // Thêm mới
  "hit_ratio": 0.968,
  "backend": "embedded",
  "memory_used_bytes": 12582912,
  "memory_max_bytes": 268435456,
  "memory_fragmentation_ratio": 1.08,
  "valkey_ops_per_sec": 2840,
  "connected_clients": 4,
  "last_updated_at": "2026-05-06T10:30:00Z"
}
```

### 6.3 Timeseries stats (polling cho chart)

```
GET /api/cache/stats/timeseries?minutes=60
```

Response: array 60 điểm, mỗi điểm:
```json
{
  "ts": "2026-05-06T09:35:00Z",
  "hits": 1240,
  "misses": 38,
  "hit_ratio": 0.97,
  "memory_used_bytes": 11200000,
  "stores": 42
}
```

Lưu timeseries vào in-memory ring buffer (60 × 1-min buckets) trong `CacheStats`.

### 6.4 Top cached routes

```
GET /api/cache/routes/top?limit=20
```

Response:
```json
[
  { "route_id": "static-assets", "hits": 45200, "misses": 120, "entry_count": 842 },
  { "route_id": "public-catalog", "hits": 12100, "misses": 840, "entry_count": 391 }
]
```

### 6.5 Tag listing

```
GET /api/cache/tags
```

Response:
```json
[
  { "tag": "static", "entry_count": 842 },
  { "tag": "catalog", "entry_count": 391 },
  { "tag": "marketing", "entry_count": 98 }
]
```

### 6.6 WebSocket stream — cache events

Thêm event type `cache_event` vào `/ws/events`:

```json
{
  "type": "cache_event",
  "ts": "2026-05-06T10:30:00Z",
  "event": "hit",        // "hit" | "miss" | "store" | "evict" | "purge_tag" | "purge_route"
  "key_prefix": "GET:example.com:/catalog/",
  "route_id": "public-catalog",
  "ttl_secs": 300
}
```

Emit sampling 1% events để không flood WebSocket.

---

## Phase 7 — Vue 3 Cache Dashboard

### 7.1 Route mới

```
/admin-panel/dashboards/cache
```

Thêm vào `web/admin-ui/src/router/index.ts`:

```ts
{
  path: '/dashboards/cache',
  component: () => import('../views/dashboards/CacheDashboard.vue'),
  meta: { requiresAuth: true }
}
```

Thêm menu item trong `Layout.vue` sidebar dưới mục "Dashboards".

### 7.2 API module mới

**`web/admin-ui/src/api/cache.ts`**

```typescript
import api from './index'

export interface CacheStats { /* map từ Phase 6.2 */ }
export interface CacheBackendInfo { /* map từ Phase 6.1 */ }
export interface CacheTimeseriesPoint { /* map từ Phase 6.3 */ }
export interface TopRoute { /* map từ Phase 6.4 */ }
export interface TagEntry { /* map từ Phase 6.5 */ }

export const cacheApi = {
  stats: ()          => api.get<CacheStats>('/api/cache/stats'),
  backend: ()        => api.get<CacheBackendInfo>('/api/cache/backend'),
  timeseries: (m=60) => api.get<CacheTimeseriesPoint[]>(`/api/cache/stats/timeseries?minutes=${m}`),
  topRoutes: (n=20)  => api.get<TopRoute[]>(`/api/cache/routes/top?limit=${n}`),
  tags: ()           => api.get<TagEntry[]>('/api/cache/tags'),
  purgeTag: (tag: string)       => api.post('/api/cache/purge/tag', { tag }),
  purgeRoute: (route_id: string) => api.post('/api/cache/purge/route', { route_id }),
  flush: ()          => api.delete('/api/cache'),
  purgeHost: (host: string) => api.delete(`/api/cache/host/${host}`),
}
```

### 7.3 View: `CacheDashboard.vue`

#### Layout tổng thể

```
┌─────────────────────────────────────────────────────────────────┐
│ Header: "Cache Dashboard"  [Backend: embedded ●]  [Refresh]     │
├──────────┬──────────┬──────────┬──────────────────────────────  │
│ Hit Ratio│  Entries │Mem Used  │ Ops/sec                        │ ← KPI row
│  96.8%   │   1,842  │ 12.0 MB  │  2,840                         │
├──────────┴──────────┴──────────┴──────────────────────────────  │
│                                                                   │
│  [Hit/Miss Timeline — 60 min area chart]                         │ ← Chart row
│                                                                   │
├────────────────────────┬────────────────────────────────────────┤
│ Top Cached Routes      │ Tag Distribution (donut)               │
│ ─────────────────────  │ ────────────────────────────────────── │
│ static-assets  45.2k   │  static 45%  catalog 21%  ...          │
│ public-catalog 12.1k   │                                         │
│ [Purge] button each    │                                         │
├────────────────────────┴────────────────────────────────────────┤
│ Backend Info                                                      │
│  Mode: embedded   Version: 7.2.4   Circuit: ● Closed             │
│  Memory: ████████░░░░░  12 MB / 256 MB  (4.7%)                   │
│  Nodes: [table nếu cluster]                                       │
├─────────────────────────────────────────────────────────────────┤
│ Actions: [Purge by Tag ▼] [Purge by Route ▼] [Flush All Cache]  │
├─────────────────────────────────────────────────────────────────┤
│ Live Cache Events (WebSocket stream, 50 entries ring buffer)     │
└─────────────────────────────────────────────────────────────────┘
```

#### Polling intervals

| Data | Interval |
|------|----------|
| KPI stats | 5s |
| Backend info | 15s |
| Timeseries | 60s |
| Top routes | 30s |
| Tags | 30s |
| Live events | WebSocket push |

#### Component breakdown

```
views/dashboards/CacheDashboard.vue       ← container, data fetching
  components/cache/
    CacheKpiRow.vue                       ← 4 KPI cards
    CacheHitMissChart.vue                 ← recharts AreaChart (hoặc Chart.js)
    CacheTopRoutesTable.vue               ← table + per-row Purge button
    CacheTagDonut.vue                     ← donut chart breakdown by tag
    CacheBackendCard.vue                  ← backend mode/version/memory bar
    CacheActionsBar.vue                   ← purge/flush action buttons + confirm modal
    CacheLiveEvents.vue                   ← WebSocket feed, monospace list
```

#### Valkey-specific display logic

```typescript
// Chỉ show khi backend != "memory"
const showValkeyInfo = computed(() => stats.backend !== 'memory')

// Memory bar
const memoryPercent = computed(() =>
  backend.memory_max_bytes > 0
    ? (backend.memory_used_bytes / backend.memory_max_bytes * 100).toFixed(1)
    : null
)

// Circuit breaker badge
const circuitColor = computed(() =>
  backend.circuit_breaker === 'closed' ? 'green'
  : backend.circuit_breaker === 'half_open' ? 'yellow'
  : 'red'
)
```

#### i18n keys cần thêm (vào tất cả 11 locales)

```json
{
  "cache": {
    "title": "Cache Dashboard",
    "hitRatio": "Hit Ratio",
    "entries": "Entries",
    "memoryUsed": "Memory Used",
    "opsPerSec": "Ops / sec",
    "backend": "Backend",
    "mode": "Mode",
    "version": "Version",
    "circuitBreaker": "Circuit Breaker",
    "topRoutes": "Top Cached Routes",
    "tagDistribution": "Tag Distribution",
    "liveEvents": "Live Cache Events",
    "purgeTag": "Purge by Tag",
    "purgeRoute": "Purge by Route",
    "flushAll": "Flush All Cache",
    "confirmFlush": "This will evict ALL cached entries. Proceed?",
    "purged": "Purged {n} entries",
    "backendInfo": "Backend Info",
    "nodes": "Nodes",
    "slots": "Slots",
    "role": "Role",
    "hitMissTimeline": "Hit / Miss Timeline (60 min)"
  }
}
```

---

## Phase 8 — Tests

### Unit tests (Rust)

**`crates/gateway/src/cache/valkey_store_test.rs`**
- `test_put_get_roundtrip` — store + retrieve entry
- `test_ttl_expiry` — entry expired after TTL
- `test_purge_by_tag` — tag set cleaned up
- `test_circuit_breaker_trips_after_threshold` — mock Valkey failure
- `test_fallback_to_moka_when_circuit_open` — reads from MokaStore

**`crates/gateway/src/cache/embedded_test.rs`**
- `test_embedded_spawn_and_ping` — spawn real valkey-server, PING
- `test_embedded_kill_on_drop` — process exits when `EmbeddedValkey` dropped

### Integration tests

**`tests/runners/cache.sh`** — new runner:
```bash
# Test 1: memory backend (baseline)
# Test 2: embedded backend — spawn, hit/miss, purge, stats
# Test 3: standalone backend — connect to test Redis, same ops
# Test 4: cluster backend — 3-node cluster, topology discovery
# Test 5: circuit breaker — kill Valkey, assert fallback active
```

### E2E — dashboard smoke test

Thêm vào `tests/runners/api.sh`:
```bash
# GET /api/cache/backend — 200, json has "backend" field
# GET /api/cache/stats   — includes new "hit_ratio", "memory_used_bytes"
# GET /api/cache/stats/timeseries?minutes=5 — array
# GET /api/cache/routes/top — array
# GET /api/cache/tags — array
```

---

## Dependency changes

### `crates/gateway/Cargo.toml`

```toml
# Valkey / Redis async client (cluster-aware, TLS, connection pool)
fred = { version = "9", features = [
    "cluster-discovery",
    "pool-prefer-active",
    "tls-rustls-native-certs",
    "monitor",
], optional = true }

[features]
default = []
valkey = ["dep:fred"]
```

Feature `valkey` mặc định **disabled** trong CI build thuần memory, **enabled** khi build production binary (Dockerfile).

### `web/admin-ui/package.json`

Không cần thêm dependency mới — dùng `axios` (có sẵn) cho API calls, `Chart.js` hoặc `recharts` cho charts (cả 2 đã có trong codebase theo codebase-summary.md).

---

## Docker & Deployment changes

### `docker-compose.yml` (single-node)

```yaml
services:
  prx-waf:
    environment:
      # Embedded mode: không cần service riêng
      CACHE_BACKEND: embedded
    volumes:
      - ./configs/default.toml:/app/configs/default.toml
```

### `docker-compose.cluster.yml` (3-node cluster)

```yaml
services:
  valkey-1:
    image: valkey/valkey:8-alpine
    command: >
      valkey-server
        --cluster-enabled yes
        --cluster-config-file /data/nodes.conf
        --cluster-node-timeout 5000
        --appendonly no
        --maxmemory 512mb
        --maxmemory-policy allkeys-lru
    ports: ["6379:6379"]

  valkey-2:
    image: valkey/valkey:8-alpine
    command: >
      valkey-server
        --cluster-enabled yes
        --cluster-config-file /data/nodes.conf
        --cluster-node-timeout 5000
        --appendonly no
        --maxmemory 512mb
        --maxmemory-policy allkeys-lru
    ports: ["6380:6379"]

  valkey-3:
    image: valkey/valkey:8-alpine
    command: >
      valkey-server
        --cluster-enabled yes
        --cluster-config-file /data/nodes.conf
        --cluster-node-timeout 5000
        --appendonly no
        --maxmemory 512mb
        --maxmemory-policy allkeys-lru
    ports: ["6381:6379"]

  valkey-init:
    image: valkey/valkey:8-alpine
    depends_on: [valkey-1, valkey-2, valkey-3]
    command: >
      sh -c "sleep 2 && valkey-cli --cluster create
        valkey-1:6379 valkey-2:6379 valkey-3:6379
        --cluster-replicas 0 --cluster-yes"
    restart: "no"

  prx-waf:
    environment:
      CACHE_BACKEND: cluster
    # default.toml mount với [cache.valkey] seeds = ["valkey-1:6379", ...]
```

---

## Config mẫu hoàn chỉnh

### `default.toml` (embedded mode)

```toml
[cache]
enabled = true
max_size_mb = 256
default_ttl_secs = 60
max_ttl_secs = 3600
rules_path = "rules/cache.yaml"
backend = "embedded"

[cache.embedded]
binary_path = ""    # auto-detect
data_dir = "/tmp/prx-valkey"
```

### `default.toml` (standalone mode)

```toml
[cache]
enabled = true
max_size_mb = 256
default_ttl_secs = 60
max_ttl_secs = 3600
rules_path = "rules/cache.yaml"
backend = "standalone"

[cache.valkey]
mode = "standalone"
seeds = ["127.0.0.1:6379"]
password = ""
pool_size = 4
connect_timeout_ms = 2000
command_timeout_ms = 500
circuit_breaker_threshold = 5
circuit_breaker_reset_secs = 30
fallback_to_memory = true
```

### `default.toml` (cluster mode)

```toml
[cache]
enabled = true
max_size_mb = 256
default_ttl_secs = 60
max_ttl_secs = 3600
rules_path = "rules/cache.yaml"
backend = "cluster"

[cache.valkey]
mode = "cluster"
seeds = ["10.0.1.1:6379", "10.0.1.2:6379", "10.0.1.3:6379"]
password = ""
tls = true
tls_ca_cert  = "/etc/prx-waf/tls/valkey-ca.pem"
pool_size = 4
connect_timeout_ms = 2000
command_timeout_ms = 500
circuit_breaker_threshold = 5
circuit_breaker_reset_secs = 30
fallback_to_memory = true
```

---

## Checklist tổng thể

### Rust backend
- [ ] P1: `CacheBackend` trait + `BackendHealth` struct
- [ ] P1: Refactor `store.rs` → `MokaStore` impl trait
- [ ] P2: `ValkeyStore` (fred client, standalone + cluster via mode flag)
- [ ] P2: Key/tag scheme (`prx:cache:*`, `prx:tag:*`, `prx:key_tags:*`)
- [ ] P2: `CircuitBreakerStore` wrapper + fallback logic
- [ ] P3: `EmbeddedValkey` supervisor (spawn, wait_ready, kill_on_drop)
- [ ] P4: Cluster topology discovery + MOVED/ASK handling (handled by fred)
- [ ] P5: TOML config structs (`EmbeddedValkeyConfig`, `ValkeyConfig`)
- [ ] P5: `CacheConfig` extended với `backend` discriminant
- [ ] P6: `GET /api/cache/backend` endpoint
- [ ] P6: Extend `GET /api/cache/stats` với memory/ops fields
- [ ] P6: `GET /api/cache/stats/timeseries` + ring buffer
- [ ] P6: `GET /api/cache/routes/top`
- [ ] P6: `GET /api/cache/tags`
- [ ] P6: WebSocket `cache_event` type (1% sampling)
- [ ] P8: Unit tests ValkeyStore
- [ ] P8: Unit tests CircuitBreaker
- [ ] P8: Integration test embedded spawn
- [ ] P8: Integration test cluster

### Vue 3 frontend
- [ ] P7: Route `/dashboards/cache` + sidebar menu item
- [ ] P7: `api/cache.ts` module với tất cả 7 endpoints
- [ ] P7: `CacheDashboard.vue` container
- [ ] P7: `CacheKpiRow.vue` — 4 KPI cards
- [ ] P7: `CacheHitMissChart.vue` — 60-min area chart
- [ ] P7: `CacheTopRoutesTable.vue` — table + per-row purge
- [ ] P7: `CacheTagDonut.vue` — donut breakdown
- [ ] P7: `CacheBackendCard.vue` — mode/version/memory bar/nodes table
- [ ] P7: `CacheActionsBar.vue` — purge/flush actions + confirm modal
- [ ] P7: `CacheLiveEvents.vue` — WebSocket feed
- [ ] P7: i18n keys thêm vào 11 locales
- [ ] P7: Polling intervals theo bảng Phase 7.3
- [ ] P7: Valkey-specific conditional display (showValkeyInfo)
- [ ] P8: API smoke tests cho 5 endpoints mới

### DevOps
- [ ] `docker-compose.yml` — env var `CACHE_BACKEND=embedded`
- [ ] `docker-compose.cluster.yml` — valkey-1/2/3 + init container
- [ ] Dockerfile — enable feature flag `--features valkey`
- [ ] Docs update: `docs/system-architecture.md`, `docs/deployment-guide.md`
