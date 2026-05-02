# cesc1802 Coding Style Analysis for prx-waf Detection Modules

**Date:** 2026-05-02  
**Researcher:** agent/researcher  
**Context:** Apply Go coding conventions from GitHub user cesc1802 to Rust 2024 WAF detection modules (XSS, Path Traversal, SSRF, Header Injection, Brute Force, Error Scanning, Body Abuse).

---

## 1. cesc1802 Profile Summary

### Public Repos Overview
- **119 public repos** across Go, TypeScript, Python, Dart, JavaScript, HCL
- **Primary language:** Go (15+ projects) — backend services, auth systems, microservices
- **Top repos by stars:**
  - `core-service` (3★) — Go service framework w/ plugin architecture
  - `mux-auth-service` (1★) — Auth/user management system
  - Others: training repos, infrastructure tools (Terraform, GitHub Actions)
- **Last activity:** Dec 2025 (consistently maintained, no abandonment)
- **Signature patterns:** DDD-influenced architecture, interface-driven design, functional options pattern

### Go Code Philosophy
1. **Interface-first design** — Small, single-purpose interfaces (Storage, Hasher, Provider)
2. **Functional options pattern** — Variadic funcs for config (e.g., `Option func(*Options)`)
3. **Explicit error types** — Custom error wrapper w/ fields: RootErr, Message, Log, Key
4. **Panic in handlers, error return in biz logic** — Clear separation
5. **Module organization** — `/biz` (business logic), `/dto` (data transfer), `/transports` (HTTP), `/storage` (persistence)
6. **Package-level variables** — `DefaultStore`, `ErrNotFound` at module scope
7. **Naming:** CamelCase entities, descriptor arrays paired w/ regex/pattern sets

---

## 2. Concrete Style Rules to Adopt (Rust Equivalents)

### Rule 1: Single-Purpose Trait Design (Mirroring Go Interfaces)

**cesc1802 Go pattern:**
```go
type Storage interface {
    Get(prefix string) (interface{}, bool)
    MustGet(prefix string) interface{}
}
type Hasher interface {
    Hash(data string) string
}
```

**Apply to Rust Detection Traits:**
```rust
// ✅ ADOPT: Minimal trait, one responsibility per trait
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
}

// ✅ ADOPT: Pair of traits for fallible/infallible variants
pub trait ConfigProvider: Send + Sync {
    fn load(&self) -> Arc<Config>;
}

pub trait ConfigReloader: Send + Sync {
    fn reload(&self, cfg: Config);
}
```

**Conflict Resolution:**  
prx-waf already follows this (trait `Check`). Continue: one trait = one detection job. Do NOT merge XSS + SSRF into a single trait.

---

### Rule 2: Functional Options Pattern for Config/DI

**cesc1802 Go pattern:**
```go
type ReadOption func(r *ReadOptions)
func ReadFrom(database, table string) ReadOption {
    return func(r *ReadOptions) {
        r.Database = database
        r.Table = table
    }
}
// Usage: store.Read(key, ReadFrom("db", "tbl"), ReadLimit(100))
```

**Apply to Rust Detection Config:**
```rust
// ✅ ADOPT: Use builder or config structs w/ default + mutation fns
pub struct XssCheckBuilder {
    cfg: XssScanConfig,
}
impl XssCheckBuilder {
    pub fn with_pattern_timeout(mut self, ms: u64) -> Self {
        self.cfg.pattern_timeout_ms = ms;
        self
    }
    pub fn build(self) -> XssCheck { XssCheck::with_config(self.cfg) }
}

// Or direct: use Arc<ArcSwap<>>  for hot-reload (already in sql_injection.rs)
```

**Current prx-waf alignment:**  
`SqlInjectionCheck` already uses `Arc<ArcSwap<SqliScanConfig>>` for hot-reload + constructor variants (`new()`, `with_config()`). This is functionally equivalent to Go options pattern. **Continue this approach.**

---

### Rule 3: Error Type w/ Structured Fields (Context + Root Cause)

**cesc1802 Go pattern:**
```go
type AppError struct {
    StatusCode int
    RootErr    error    // wrapped internal error
    Message    string   // user-facing
    Log        string   // log-friendly
    Key        string   // error code (e.g., "ErrCannotGetUser")
}
```

**Apply to Rust Detection Errors:**
```rust
// ✅ ADOPT: Use anyhow::Context or a custom Result type
use anyhow::{anyhow, Context, Result};

pub struct DetectionError {
    pub phase: Phase,
    pub rule_id: Option<String>,
    pub message: String,
    pub source: Option<String>,  // root cause
}

// Usage in checks:
let matches = SQLI_SET.matches(&value)
    .context("Failed to scan for SQL injection patterns")?;
```

**Current prx-waf alignment:**  
Already uses `Option<DetectionResult>` for detections. Add explicit error handling for pattern compilation failures (already done w/ `.log_error()` in XSS_SET). Use `anyhow::Context` for multi-step operations (pattern load, regex compile).

---

### Rule 4: Descriptor Array + Pattern Set Pairing

**cesc1802 Go pattern (inferred from core-service):**  
Named config structs paired w/ interface implementations. In prx-waf, descriptive arrays + regex sets are already used:

```go
// Go-equivalent: const-like storage of descriptions
var (
    SqliDescs = []string{"String concat", "Union select", ...}
    SqliPatterns = []Regex{...}
)
```

**prx-waf Rust pattern (ALREADY ADOPTED):**
```rust
static XSS_DESCS: &[&str] = &[
    "<script> tag",
    "event handler attribute (on*=)",
    ...
];
static XSS_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)<\s*/?\s*script[\s/>]",
        ...
    ]).unwrap_or(RegexSet::empty())
});
```

**Keep as-is.** This mirrors Go's approach: parallel arrays of descriptions + patterns, accessed by matched index.

---

### Rule 5: Configuration-Driven Enable/Disable Logic

**cesc1802 pattern (mux-auth-service):**  
Config passed down through dependency chain; handlers check `ctx.config` before proceeding.

```go
func UserLogin(ac appctx.AppContext) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        cfg := ac.Config()  // retrieve once per request
        if !cfg.Auth.Enabled { return }
        ...
    }
}
```

**prx-waf Rust pattern (ALREADY ADOPTED):**
```rust
impl Check for XssCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.xss {
            return None;  // gate early
        }
        // proceed only if enabled
    }
}
```

**No change needed.** Continue early-return pattern for all detection modules.

---

### Rule 6: Test Structure — Per-Module Fixtures + Data-Driven Cases

**cesc1802 Go pattern (implied from project structure):**  
Module has internal test helpers (`/biz`, `/storage` each have test files in same package).

```go
// file: user_login_test.go (in same package as user_login.go)
func TestUserLoginSuccess(t *testing.T) { ... }
func TestUserLoginInvalidPassword(t *testing.T) { ... }
```

**prx-waf Rust pattern (ALREADY ADOPTED):**
```rust
// file: xss.rs
#[cfg(test)]
mod tests {
    fn make_ctx(query: &str, body: &str) -> RequestCtx { ... }
    
    #[test]
    fn detects_script_tag() { ... }
    
    #[test]
    fn detects_event_handler() { ... }
}
```

**Keep as-is.** Inline tests in each module, helper `make_ctx()` to reduce boilerplate.

---

### Rule 7: Comment Style — Short, Action-Focused, Mark Safety

**cesc1802 pattern:**  
Comments explain "why" not "what". Example from core-service:
```go
// Options contains configuration for the Store
type Options struct {
    // Nodes contains the addresses or other connection information of the backing storage.
    Nodes []string
    ...
}
```

**Apply to Rust Detection Modules:**
```rust
/// Trait implemented by every WAF checker module.
///
/// Each checker is stateless (detection patterns) or uses interior mutability
/// (CC rate limiter). The pipeline calls `check()` in sequence and
/// short-circuits on the first `Some(result)`.
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
}

// SAFETY: All patterns are compile-time string literals. If any pattern fails
// to compile it is a code bug that must be caught in development, not at runtime.
static XSS_SET: LazyLock<RegexSet> = LazyLock::new(|| { ... });
```

**Adopt:** Doc comments above types/traits (3-liner max). Inline comments for non-obvious logic (e.g., SAFETY on regex compile).

---

## 3. Conflicts with Current prx-waf Style & Resolutions

| Aspect | cesc1802 Go | Current prx-waf Rust | Resolution |
|--------|------------|-------------------|-----------|
| Error handling | `panic()` in handlers, error return in biz | `Option<T>`, `?`, `anyhow` | Keep as-is; Rust requires explicit error handling. Use `anyhow::Context` for multi-step ops. |
| Config hot-reload | Config passed through context on each request | `Arc<ArcSwap<>>` in struct | Rust approach is better (lock-free reads). Continue. |
| Trait design | Minimal, single-method interfaces | Single-method trait `Check` | Perfect alignment. Continue. |
| Naming | CamelCase entities + verb-noun descriptors | `XssCheck`, `SqlInjectionCheck` + `DESCS` arrays | Align: use noun-Check pattern. Descriptor arrays already follow cesc1802 style. |
| Test organization | One test file per module | Inline `#[cfg(test)]` mod | Inline is acceptable for Rust. Keep (no cost to readability). |
| Comments | Doc comments on types, inline on logic | Already present in xss.rs, mod.rs | Continue. Mark unsafe blocks and regex compile-time assertions. |

**No major conflicts.** Style is already aligned at architectural level.

---

## 4. Actionable Recommendations for New Detection Modules

### For XSS, Path Traversal, SSRF, Header Injection, Brute Force, Error Scanning, Body Abuse:

**1. Module Structure (apply cesc1802 DDD-style organization):**
```
checks/
├── xss.rs                      # detector struct + Check trait impl
├── xss_patterns.rs             # static DESCS + LazyLock SET
├── xss_scanners.rs             # internal: scan_headers(), scan_json_body()
└── (repeat for each module)
```

**2. Detector Struct Pattern:**
```rust
/// [Phase] detection checker with optional hot-reloadable config.
pub struct [Phase]Check {
    cfg: Arc<ArcSwap<[Phase]ScanConfig>>,  // or LazyLock if stateless
}

impl [Phase]Check {
    pub fn new() -> Self { Self::with_config([Phase]ScanConfig::default()) }
    pub fn with_config(cfg: [Phase]ScanConfig) -> Self { ... }
    pub fn reload_config(&self, cfg: [Phase]ScanConfig) { ... }  // if hot-reload needed
}

impl Default for [Phase]Check { fn default() -> Self { Self::new() } }
impl Check for [Phase]Check { fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> { ... } }
```

**3. Pattern Descriptor Pairing:**
```rust
static [PHASE]_DESCS: &[&str] = &[
    "Evasion technique 1",
    "Evasion technique 2",
    ...
];

static [PHASE]_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([...]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: [PHASE] regex set failed: {e}");
            RegexSet::empty()
        }
    }
});
```

**4. Scanner Functions (for complex phases like Path Traversal, SSRF):**
```rust
fn scan_query_params(query: &str, set: &RegexSet) -> Option<(String, usize)> {
    // Returns (location: "query?param=name", matched_idx)
}
fn scan_headers(headers: &HashMap<String, String>, cfg: &[Phase]ScanConfig, set: &RegexSet) 
    -> Option<(String, usize)> 
{
    // Respects cfg.header_allowlist / denylist
}
fn scan_json_body(body: &str, set: &RegexSet, parse_cap: usize) -> Option<(String, usize)> {
    // Respects parse size cap
}
```

**5. Test Fixture (cesc1802-inspired):**
```rust
#[cfg(test)]
mod tests {
    fn make_ctx(path: &str, query: &str, headers: HashMap<String, String>, body: &str) -> RequestCtx {
        RequestCtx {
            // ... defaults ...
            path: path.to_string(),
            query: query.to_string(),
            headers,
            body_preview: Bytes::from(body.to_string()),
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    [phase]: true,  // enable this check
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn detects_payload_1() { ... }
    #[test]
    fn detects_payload_2() { ... }
    #[test]
    fn allows_clean_request() { ... }
}
```

**6. Error Handling (use anyhow for regex failures):**
```rust
use anyhow::{Context, Result};

impl Check for [Phase]Check {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.[phase] {
            return None;
        }
        
        for (location, value) in request_targets(ctx) {
            let matches = [PHASE]_SET.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = [PHASE]_DESCS.get(idx).copied().unwrap_or("[PHASE] pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("[PHASE]-{:03}", idx + 1)),
                    rule_name: "[Phase]".to_string(),
                    phase: Phase::[Phase],
                    detail: format!("{desc} detected in {location}"),
                });
            }
        }
        None
    }
}
```

---

## Summary: Style Integration

✅ **Already aligned with cesc1802:**
- Single-method trait design (Check trait)
- Configuration passed via struct, early-return gating
- Descriptor + pattern set pairing (DESCS + RegexSet)
- Inline module tests w/ fixtures
- Lock-free hot-reload (Arc<ArcSwap<>> surpasses Go options pattern)
- Doc comments on types + inline comments on safety/non-obvious code

✅ **To adopt going forward:**
- Use `make_ctx()` helper to reduce test boilerplate (already in xss.rs)
- Mark regex compile-time assertions w/ `// SAFETY:` comment
- Use `anyhow::Context` for multi-step pattern-load operations
- Consistent `{:03}` rule ID formatting (already done in sql_injection.rs)

❌ **Not applicable (Go-specific):**
- Panic in handlers (Rust forbids at call site; return Result instead)
- Functional options as variadic params (Rust uses builder or config struct)
- Custom error wrapper w/ StatusCode (HTTP layer handles this, not checker)

---

## Unresolved Questions

1. **SSRF module:** Should we add DNS caching / pre-resolve common cloud metadata endpoints? cesc1802 code doesn't cover network checks; recommend consulting security team for scope.

2. **Body Abuse module:** Size thresholds for request/response payloads? Depends on tier policy; reference `tier_policy` in RequestCtx.

3. **Header Injection module:** Should allowlist common safe headers (e.g., User-Agent, Accept)? Current approach (pattern-based block) vs. allowlist? No precedent in cesc1802; recommend threat model review.

4. **Error Scanning module:** Should we suppress stack trace leaks at detector level or at response layer? cesc1802 code doesn't cover this; likely application-layer concern.

5. **Brute Force module:** Should integrate w/ CC (rate limit) checker or be separate? Both are stateful; recommend architectural alignment with existing cc.rs.
