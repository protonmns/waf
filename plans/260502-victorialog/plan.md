# Implementation Plan: VictoriaLogs Integration với mini-waf

---

## Tổng quan

Tích hợp VictoriaLogs vào `prx-waf` binary như một managed sidecar process. WAF tự download binary khi chưa có, spawn khi boot, shutdown gracefully khi exit. Log pipeline tách thành 2 independent layers: `tracing` subscriber và audit log. React admin panel có trang log viewer query qua proxy API với credential của admin panel.

---

## Phạm vi thay đổi

### Crates backend

| Crate | File | Loại thay đổi |
|-------|------|---------------|
| `waf-common` | `src/config.rs` | Thêm `VictoriaLogsConfig` struct |
| `gateway` | `src/logging/mod.rs` | Module mới — logging pipeline |
| `gateway` | `src/logging/vlogs_layer.rs` | `tracing` Layer ghi vào VictoriaLogs |
| `gateway` | `src/logging/audit_sender.rs` | Audit event sender độc lập với tracing |
| `gateway` | `src/logging/batch_buffer.rs` | Shared async batch/flush logic |
| `prx-waf` | `src/main.rs` | Khởi tạo sidecar và logging pipeline |
| `prx-waf` | `src/victoria_logs/mod.rs` | Module mới — sidecar management |
| `prx-waf` | `src/victoria_logs/installer.rs` | Download và verify binary |
| `prx-waf` | `src/victoria_logs/sidecar.rs` | Spawn, monitor, shutdown child process |

### Frontend

| File | Loại thay đổi |
|------|---------------|
| `src/providers/victoriaLogsDataProvider.ts` | Refine dataProvider mới |
| `src/pages/logs/index.tsx` | Trang log viewer |
| `src/pages/logs/LogsTable.tsx` | Bảng hiển thị log entries |
| `src/pages/logs/LogsFilters.tsx` | Filter panel theo rule, IP, tier, time |
| `src/pages/logs/LogsQueryBar.tsx` | Raw LogsQL query input |

### Config / Docs

| File | Thay đổi |
|------|----------|
| `configs/default.toml` | Thêm `[victoria_logs]` section |
| `docs/system-architecture.md` | Thêm logging architecture section |

---

## Phase 01 — Config, Installer, Sidecar

**Goal:** WAF tự cài đặt và quản lý VictoriaLogs binary. Operator không cần cài thủ công.

### 1.1 `VictoriaLogsConfig`

Thêm vào `waf-common/src/config.rs` sau `ThreatIntelConfig`. Các fields:

- `enabled: bool` — default `false`, opt-in
- `binary_path: String` — đường dẫn tới binary trên disk
- `storage_data_path: String` — thư mục lưu data partitions
- `listen_addr: String` — bắt buộc loopback (`127.0.0.1:9428`), validate ở load time để tránh expose ra ngoài vì VictoriaLogs không có built-in auth
- `retention_period: String` — default `"30d"`, time-based retention
- `max_disk_space_bytes: String` — default `"100GiB"`, size-based cap, xóa oldest partition khi vượt
- `min_free_disk_bytes: String` — default `"1GiB"`, safety stop khi disk sắp đầy
- `version: String` — release tag để download, ví dụ `"v1.50.0"`
- `auto_install: bool` — default `true`, tự download nếu binary chưa có

Thêm `victoria_logs.validate()` vào `load_config()`. Validation kiểm tra `listen_addr` bắt buộc là loopback, `storage_data_path` không rỗng, reject non-loopback address với error message rõ ràng giải thích lý do bảo mật.

Thêm 2 helper methods: `ingest_url()` trả về URL endpoint JSON Lines ingest, `query_url()` trả về URL endpoint LogsQL query.

### 1.2 Installer (`prx-waf/src/victoria_logs/installer.rs`)

Chịu trách nhiệm đảm bảo binary sẵn sàng trước khi spawn.

**Logic:**
1. Kiểm tra `binary_path` đã tồn tại chưa. Nếu có thì skip.
2. Nếu không có và `auto_install = false` thì return error yêu cầu operator cài thủ công.
3. Nếu `auto_install = true` thì tiến hành download.
4. Platform detection qua `std::env::consts::{OS, ARCH}` để chọn đúng artifact URL. Hỗ trợ: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`. Các platform khác return error rõ ràng.
5. Download archive từ GitHub releases URL dạng `https://github.com/VictoriaMetrics/VictoriaLogs/releases/download/{version}/victoria-logs-{os}-{arch}-{version}.tar.gz`
6. Download file checksum `.sha256` từ cùng release.
7. Verify SHA256 trước khi giải nén. Fail nếu checksum không khớp — không bao giờ exec binary chưa được verify.
8. Giải nén vào temp directory, move binary vào `binary_path` atomically.
9. Set executable permission (`chmod +x`).
10. Log mỗi bước với `tracing::info!` để operator thấy tiến trình khi boot.

**Error cases cần handle rõ:**
- Network không available
- Checksum mismatch (log cả expected vs actual)
- `binary_path` parent directory không tồn tại hoặc không có write permission
- Unsupported platform

### 1.3 Sidecar (`prx-waf/src/victoria_logs/sidecar.rs`)

Quản lý lifecycle của VictoriaLogs child process.

**Struct `VictoriaLogsSidecar`** giữ:
- `child: tokio::process::Child`
- `config: Arc<VictoriaLogsConfig>`
- `abort_handle` cho health-check task

**Spawn logic:**
- Gọi `tokio::process::Command` với đầy đủ flags từ config:
  - `--storageDataPath`
  - `--httpListenAddr`
  - `--retentionPeriod`
  - `--retention.maxDiskSpaceUsageBytes`
  - `--storage.minFreeDiskSpaceBytes`
- Redirect stdout/stderr của child vào `tracing::info!`/`tracing::warn!` của WAF để log tập trung — không để VictoriaLogs logs lẫn với stdout của WAF.
- Tạo `storage_data_path` nếu chưa tồn tại trước khi spawn.

**Health check task:**
- Sau khi spawn, chờ tối đa 10 giây cho VictoriaLogs sẵn sàng bằng cách poll `GET http://{listen_addr}/health` mỗi 500ms.
- Nếu không ready sau 10 giây thì return error rõ ràng.
- Sau khi ready, spawn một background task health-check mỗi 30 giây. Nếu process exit unexpectedly thì log error, không tự restart (tránh restart loop; operator cần xem xét).

**Drop/shutdown:**
- `impl Drop for VictoriaLogsSidecar`: gửi SIGTERM tới child, đợi tối đa 5 giây cho graceful shutdown, sau đó SIGKILL nếu vẫn còn sống.
- Đảm bảo abort health-check task trong Drop.

### 1.4 Wiring vào `main.rs`

Trong `init_async()`, sau khi load config và trước khi init engine:

1. Gọi `installer::ensure_binary(&config.victoria_logs).await?` — fail-fast nếu binary không ready.
2. Gọi `VictoriaLogsSidecar::spawn(&config.victoria_logs).await?` — spawn và chờ health check.
3. Store sidecar handle trong `AppState` hoặc giữ trong local variable để Drop chạy khi process exit.
4. Nếu `victoria_logs.enabled = false` thì toàn bộ flow này là no-op — zero cost.

---

## Phase 02 — Dual-Layer Logging Pipeline

**Goal:** Tách biệt hoàn toàn 2 concerns: observability (`tracing` events) và security audit log (WAF block/allow events). Hai layer có buffer riêng, flush riêng, fail-open độc lập.

### 2.1 Shared Batch Buffer (`gateway/src/logging/batch_buffer.rs`)

Component dùng chung cho cả 2 layer. Là một async buffer với:

- Giữ queue các JSON objects pending flush.
- Flush khi đạt `batch_size` (default 100 entries) HOẶC sau `flush_interval` (default 1 giây), whichever comes first.
- Nếu VictoriaLogs không available (network error, process down): log warn một lần, drop batch, tiếp tục — không bao giờ block WAF request path.
- Dùng `tokio::sync::mpsc` channel để tách write path (hot path của WAF) khỏi flush path (background task).
- Background flush task giữ một `reqwest::Client` với timeout 5 giây cho mỗi batch send.
- Khi buffer đầy (channel full): drop oldest entries, emit `tracing::warn!` một lần — tránh memory growth không giới hạn.

**Config fields** (trong `VictoriaLogsConfig`):
- `batch_size: usize` — default 100
- `flush_interval_ms: u64` — default 1000
- `channel_capacity: usize` — default 10_000

### 2.2 Tracing Layer (`gateway/src/logging/vlogs_layer.rs`)

Implement `tracing_subscriber::Layer` để capture `tracing` events và gửi vào VictoriaLogs.

**Behavior:**
- `on_event()`: convert `tracing::Event` sang JSON object với các fields:
  - `_msg`: message string
  - `_time`: RFC3339 timestamp
  - `level`: `"ERROR"`, `"WARN"`, `"INFO"`, `"DEBUG"`
  - `target`: module path (ví dụ `"gateway::proxy"`)
  - `span_fields`: tất cả fields từ current span context (ví dụ `host`, `req_id`, `client_ip` nếu có trong span)
  - Tất cả event fields giữ nguyên tên
- Gửi vào batch buffer async — `on_event()` không block.
- Filter theo level: chỉ forward `INFO` và trên trong production, `DEBUG` khi cờ debug được bật.
- Không capture log của VictoriaLogs process chính nó để tránh loop.

**Composition:** Layer này được thêm vào `tracing_subscriber` registry cùng với layer hiện có (stderr/stdout). Cả 2 layer chạy song song, không thay thế nhau.

### 2.3 Audit Sender (`gateway/src/logging/audit_sender.rs`)

Layer thứ 2 hoàn toàn độc lập với `tracing`. Chịu trách nhiệm gửi WAF security events.

**`AuditEvent` struct** — các fields:
- `_time`: timestamp
- `_msg`: human-readable summary
- `event_type`: `"block"`, `"allow"`, `"challenge"`, `"rate_limit"`
- `rule_name`: tên rule đã trigger
- `rule_id`: optional rule ID
- `phase`: detection phase
- `client_ip`: IP sau canonicalize
- `host`: target host
- `method`: HTTP method
- `path`: request path (truncate tại 500 chars)
- `tier`: `"Critical"`, `"High"`, `"Medium"`, `"CatchAll"`
- `detail`: chi tiết detection
- `req_id`: request ID để correlate với tracing logs

**Integration point:** `AuditSender` được thêm vào `WafEngine` hoặc truyền vào `WafProxy` tương tự `body_mask_cache`. Trong `engine.rs`, mỗi khi `inspect()` trả về non-Allow decision thì gọi `audit_sender.send(event)` — fire-and-forget, không block.

**Phân biệt với tracing layer:**
- Tracing layer: observability — logs tất cả events kể cả internal WAF processing
- Audit sender: security record — chỉ log access decisions, luôn có `client_ip` + `rule_name`, dùng cho SIEM/compliance

---

## Phase 03 — Proxy API (Rust backend)

**Goal:** Expose LogsQL query ra ngoài qua WAF API với JWT auth. VictoriaLogs port 9428 không bao giờ accessible ngoài loopback.

### 3.1 Endpoints trong `waf-api`

**`GET /api/v1/logs/query`**
- Query params: `query` (LogsQL string), `start`, `end`, `limit` (max 5000)
- Auth: existing JWT middleware, role `admin` required
- Logic: validate params, forward tới `http://127.0.0.1:9428/select/logsql/query`, stream response về client
- Rate limit: 10 requests/second per user để tránh heavy query DoS

**`GET /api/v1/logs/stats`**
- Trả về: tổng số log entries 24h, disk usage, retention info
- Fetch từ VictoriaLogs metrics endpoint và format lại

**`GET /api/v1/logs/streams`**
- Trả về danh sách log streams (distinct values của `event_type`, `rule_name`, `tier`) để FE populate filter dropdowns
- Cache 60 giây để tránh expensive query lặp lại

### 3.2 Security constraints

- `listen_addr` validate là loopback ở config load time (Phase 01)
- Proxy không forward tới bất kỳ URL nào khác ngoài configured `query_url()` — không có SSRF risk
- LogsQL query không được phép contain `| delete` hoặc write operations — server-side validation
- Response size capped tại 50MB trước khi stream về client

---

## Phase 04 — React Log Viewer FE

**Goal:** Trang `/logs` trong admin panel với credential hiện có, dùng Ant Design components nhất quán với phần còn lại của panel.

### 4.1 VictoriaLogs Data Provider (`src/providers/victoriaLogsDataProvider.ts`)

Implement Refine `DataProvider` interface chỉ cho resource `logs`.

**`getList`:** Convert Refine filter objects sang LogsQL syntax, call `/api/v1/logs/query`, parse response, trả về `{ data, total }`.

**Filter → LogsQL mapping:**

| Refine filter | LogsQL expression |
|---------------|-------------------|
| `rule_name eq "sqli"` | `rule_name:sqli` |
| `tier eq "Critical"` | `tier:Critical` |
| `client_ip eq "1.2.3.4"` | `client_ip:"1.2.3.4"` |
| `event_type eq "block"` | `event_type:block` |
| `_msg contains "injection"` | `injection` (full-text) |
| time range | `_time:[start, end]` |

**Error handling:** network error → Refine notification, không crash trang.

### 4.2 Trang Log Viewer (`src/pages/logs/index.tsx`)

Layout dùng Ant Design, nhất quán với các trang khác trong panel:

**`LogsFilters` component** — sidebar filter panel:
- Time range picker (Ant Design DatePicker.RangePicker) với preset: Last 1h, Last 6h, Last 24h, Last 7d
- `event_type` dropdown: All, Block, Allow, Rate Limit, Challenge
- `tier` multi-select: Critical, High, Medium, CatchAll
- `rule_name` searchable dropdown (populate từ `/api/v1/logs/streams`)
- Client IP text input với basic IPv4/IPv6 validation
- Free-text search (full-text qua LogsQL)
- Raw LogsQL input toggle cho advanced users — hiện/ẩn filter panel khi dùng raw mode

**`LogsQueryBar` component:**
- Hiển thị LogsQL query đang active (read-only khi dùng filter panel)
- Chuyển sang editable raw mode khi click "Advanced"
- "Copy query" button để copy LogsQL ra clipboard

**`LogsTable` component:**
- Cột: Time, Event Type, Rule Name, Client IP, Host, Tier, Detail
- Row expand để xem full JSON của log entry
- Pagination server-side, page size 50/100/500
- `event_type = "block"` render Tag màu đỏ, `"allow"` màu xanh, `"rate_limit"` màu vàng
- Column `client_ip` có link "→ Filter by this IP" để set filter nhanh
- Column `rule_name` có link "→ Filter by this rule"
- Auto-refresh toggle: off mặc định, có thể bật với interval 10s/30s/60s

**Trang layout:**
- Header: title "Security Logs" + stats bar nhỏ (tổng entries 24h, disk usage)
- Body: filter sidebar bên trái (collapsible) + table bên phải
- Empty state khi không có log: hướng dẫn enable VictoriaLogs trong config

### 4.3 Route và Navigation

- Thêm route `/logs` vào React Router config
- Thêm menu item "Security Logs" vào sidebar navigation với icon phù hợp
- Trang chỉ accessible với role `admin` — guard ở route level dùng Refine `canAccess`

---

## Disk Budget — cơ chế hoạt động

Ba flag phối hợp với nhau để bảo vệ disk:

**Size-based cap** (`retention.maxDiskSpaceUsageBytes=100GiB`): Khi tổng data vượt 100GiB, VictoriaLogs tự xóa oldest daily partition. Đây là hard ceiling, tác động trước retention period.

**Time-based retention** (`retentionPeriod=30d`): Partition cũ hơn 30 ngày bị xóa tự động bất kể disk usage. Soft floor.

**Safety stop** (`storage.minFreeDiskSpaceBytes=1GiB`): Khi filesystem còn dưới 1GiB free, VictoriaLogs dừng nhận log mới, trả HTTP 503 cho ingest requests. WAF log pipeline fail-open khi nhận 503 — drop batch, warn một lần, tiếp tục hoạt động. WAF không bao giờ bị block vì VictoriaLogs đầy disk.

**Khuyến nghị config theo môi trường:**

| Môi trường | `max_disk_space_bytes` | `retention_period` |
|------------|------------------------|-------------------|
| Hackathon / dev | `10GiB` | `7d` |
| Production nhỏ | `50GiB` | `30d` |
| Production đầy đủ | `100GiB` | `30d` |

---

## Security boundaries không thay đổi

- Port 9428 chỉ bind loopback, validate ở config load, reject non-loopback với error message
- VictoriaLogs không có auth — toàn bộ query từ FE đi qua Rust proxy với JWT check
- Binary installer verify SHA256 trước khi exec — không exec binary chưa verify
- LogsQL proxy không cho phép write/delete operations
- Audit log không lưu request body — chỉ metadata (IP, path, rule, decision)

---

## Acceptance criteria

**Phase 01:**
- WAF boot thành công với `auto_install = true` trên Linux/amd64 và Linux/arm64 trên máy chưa có binary
- WAF boot thành công với `auto_install = false` khi binary đã có sẵn
- VictoriaLogs exit unexpected → WAF log error, tiếp tục serve traffic
- WAF shutdown → VictoriaLogs nhận SIGTERM, tắt trong vòng 5 giây

**Phase 02:**
- `tracing::warn!("test")` trong WAF code → entry xuất hiện trong VictoriaLogs trong vòng 2 giây
- WAF block một request → audit event có đủ fields xuất hiện trong VictoriaLogs trong vòng 2 giây
- VictoriaLogs tắt đột ngột → WAF tiếp tục serve traffic, log warn mỗi 30 giây, không panic

**Phase 03:**
- `GET /api/v1/logs/query` không có JWT → 401
- `GET /api/v1/logs/query` với role non-admin → 403
- Query hợp lệ với JWT admin → kết quả từ VictoriaLogs trong vòng 500ms với data nhỏ

**Phase 04:**
- Đăng nhập admin panel → thấy menu "Security Logs"
- Filter theo `event_type=block` → chỉ thấy block events
- Raw LogsQL query `client_ip:"1.2.3.4"` → filter đúng
- Auto-refresh 10s → table update không reload cả trang

---

## Out of scope (explicit)

- Cluster mode VictoriaLogs — single-node đủ cho hackathon
- Compressed body log — audit log chỉ metadata
- VictoriaLogs metrics/alerting (vmalert) — separate plan
- Custom retention per log stream — một policy cho tất cả
- Log export/backup ra S3/GCS — future plan
- Grafana integration — vmui của VictoriaLogs đủ cho hackathon