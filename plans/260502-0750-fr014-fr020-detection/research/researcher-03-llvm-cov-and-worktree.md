---
name: cargo-llvm-cov Docker Coverage + Parallel Worktree Spec
description: Actionable spec for per-crate coverage gates in Docker (>=90%) and 7-branch parallel worktree workflow with gh PR automation
type: research
---

# Section 1: cargo-llvm-cov Docker Coverage Gate (>=90% per-crate)

## Current State

- **cargo-llvm-cov latest:** 0.8.5 (released Mar 2026) [source: crates.io]
- **Known bug:** In 0.8.5, `--fail-under-lines` is **ignored** when combined with `--ignore-filename-regex` (documented in existing CI, lines 65–100)
- **Root cause:** LLVM-cov's ignore-list regex filtering happens *after* coverage calculation, so `--fail-under-lines` sees the filtered-out files excluded from total % (off-by-one in denominator)
- **Status:** Bug still present in 0.8.5; not fixed as of Feb 2025 cutoff

## Recommended Approach: Fallback Parsing

**Why:** Don't wait for upstream fix. Parse `cargo llvm-cov --lcov` output with `awk` to extract per-crate % from the TOTAL line, then enforce gate locally. Matches existing CI pattern (line 91–94).

### Dockerfile.coverage (Single-Stage, Layer-Cached)

```dockerfile
FROM rust:1.91-slim-bookworm

WORKDIR /build

# Install build + coverage deps (llvm-tools, cargo-llvm-cov)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Pre-install cargo-llvm-cov (cached layer)
RUN cargo install cargo-llvm-cov --locked --version 0.8.5

# Copy workspace files (cache friendly)
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/
RUN mkdir -p crates/{prx-waf,gateway,waf-api,waf-cluster,waf-common,waf-engine,waf-storage}/src

# Stub source layer (cache hit for unchanged code)
RUN for crate in prx-waf gateway waf-api waf-cluster waf-common waf-engine waf-storage; do \
      echo 'fn main(){}' > crates/$crate/src/main.rs 2>/dev/null || \
      echo 'pub fn dummy(){}' > crates/$crate/src/lib.rs; \
    done

# Pre-build deps (cached if Cargo.lock unchanged)
RUN cargo build --release 2>/dev/null || true

# Copy real source
COPY . .

# Run coverage and output to /out/lcov.info
RUN mkdir -p /out && \
    cargo llvm-cov --workspace --lcov --output-path /out/lcov.info \
      --exclude-regex '/tests/|/benches/' \
      2>&1 | tee /out/cov-summary.txt

# Per-crate gates (see enforcement script below)
RUN bash /coverage-gate.sh

COPY --chown=nobody:nogroup /out /coverage
```

### Coverage Gate Script (`scripts/coverage-gate.sh`)

Save as `/Users/admin/lab/mini-waf/scripts/coverage-gate.sh`:

```bash
#!/bin/bash
set -e

SUMMARY_FILE="${1:-/out/cov-summary.txt}"
GATE_PCT="${2:-90}"
FAILED=0

# Extract per-crate coverage from llvm-cov summary
# Expected format: "waf-engine: 87.5 / 100"
awk -v gate="$GATE_PCT" '
  /^(prx-waf|gateway|waf-api|waf-cluster|waf-common|waf-engine|waf-storage):/ {
    gsub("%", "", $NF)
    pct = $NF + 0
    crate = $1; gsub(":", "", crate)
    if (pct < gate) {
      print "ERROR: " crate " coverage " pct "% < " gate "%"
      exit 1
    } else {
      print "OK: " crate " coverage " pct "%"
    }
  }
' "$SUMMARY_FILE"
```

### Docker Compose Recipe (Named Volume, No Host Pollution)

Add to `docker-compose.yml`:

```yaml
services:
  coverage:
    build:
      context: .
      dockerfile: Dockerfile.coverage
    image: prx-waf:coverage-latest
    volumes:
      - waf-coverage-target:/build/target  # Named volume, isolates host
    command: /bin/true  # Build-only, no runtime
    profiles: ["tools"]  # Optional profile: only run with `docker compose --profile tools up`

volumes:
  waf-coverage-target:
    driver: local
```

### Makefile One-Liner (Local Dev)

Add to `/Users/admin/lab/mini-waf/Makefile`:

```makefile
.PHONY: coverage coverage-fr% coverage-clean

coverage:
	@echo "Running full workspace coverage (>=90% gate)..."
	docker build -f Dockerfile.coverage -t prx-waf:cov .
	docker run --rm -v prx-waf-cov-target:/build/target prx-waf:cov

coverage-fr%:
	@crate=$$(echo $@ | sed 's/coverage-//'); \
	echo "Running coverage for $$crate only..."; \
	docker run --rm -v prx-waf-cov-target:/build/target \
	  -e CARGO_PKG_NAME=$$crate \
	  prx-waf:cov cargo llvm-cov -p $$crate --lcov \
	    --fail-under-lines 90 \
	    --output-path /out/$${crate}-lcov.info 2>&1 | tee /out/$${crate}-cov.txt

coverage-clean:
	docker volume rm prx-waf-cov-target 2>/dev/null || true

# Usage: make coverage-fr016 (runs waf-engine coverage only)
```

### CI Integration (Uncomment & Adapt)

**File:** `.github/workflows/ci.yml`, lines 65–101, replace with:

```yaml
  coverage:
    name: Per-Crate Coverage (>=90%)
    needs: lint
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Run workspace coverage
        run: |
          cargo llvm-cov --workspace --lcov \
            --output-path lcov.info \
            --exclude-regex '/tests/|/benches/' \
            2>&1 | tee cov-summary.txt

      - name: Enforce per-crate >=90% gate
        run: |
          bash scripts/coverage-gate.sh cov-summary.txt 90

      - name: Upload lcov for external tools
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: coverage-lcov
          path: lcov.info
```

## Key Design Decisions

| Decision | Why |
|----------|-----|
| Parse output, not CLI flag | `--fail-under-lines` + `--ignore-filename-regex` bug in 0.8.5; no fix ETA |
| Named volume in Docker | Avoids host `target/` bloat; can `make coverage-clean` to reset |
| Dockerfile.coverage separate | Distinct from build Dockerfile (Dockerfile.prebuilt); reusable for CI |
| Per-crate gate via script | Extensible; easy to add crate-specific thresholds if needed |
| Makefile target | Dev-local; mirrors CI gate; `make coverage-fr016` runs waf-engine only |

## Coverage Scope

- **Includes:** All crate source in `crates/*/src` (except stubs)
- **Excludes:** `/tests/`, `/benches/` (test files inflates denominator)
- **Scoped for FR-014..FR-020:** Focus on `crates/waf-engine/src/checks/{xss,dir_traversal,scanner,ssrf,header_injection,brute_force,body_abuse}.rs` if partial gate needed later

---

# Section 2: Parallel Worktree + GH PR Workflow

## Conflict Prevention Strategy: Recommended Approach (c)

**Chunked Dispatcher via inventory! macro**

### Why Not (a) or (b)?

| Strategy | Pros | Cons | Verdict |
|----------|------|------|---------|
| **(a) Phase-0 merge + branch off** | Clean merge tree; no conflicts | Slow; sequential bottleneck; blocks 7 branches until phase-0 merged | ❌ Violates parallelism |
| **(b) Each branch edits shared, merge PR queue resolves** | Maximal parallelism | Rebase storm; each PR merge forces rebase of 6 siblings; high conflict cost | ❌ N² rebase friction |
| **(c) inventory! dispatcher** | O(1) registration; no mod.rs edits; true parallelism | Requires init PR adding macro framework | ✅ **RECOMMEND** |

### Approach (c): inventory! macro registration

**File:** `crates/waf-engine/src/checks/mod.rs` (ONE edit, once)

```rust
pub mod anti_hotlink;
pub mod bot;
pub mod cc;
pub mod dir_traversal;
pub mod geo;
pub mod owasp;
pub mod rce;
pub mod scanner;
pub mod sensitive;
pub mod sql_injection;
pub(crate) mod sql_injection_patterns;
pub(crate) mod sql_injection_scanners;
pub mod xss;

// NEW CHECKS: Each branch adds new module + registers below (NO mod.rs edit needed)
pub mod ssrf;        // FR-015
pub mod header_injection; // FR-016
pub mod brute_force;  // FR-017
pub mod body_abuse;   // FR-018

pub use /* ...existing exports... */;

use inventory::submit;

// Trait for auto-registration
pub trait CheckFactory: Send + Sync {
    fn name(&self) -> &'static str;
    fn create(&self) -> Box<dyn Check>;
}

// Inventory collection (compile-time macro)
pub struct CheckRegistry;
impl CheckRegistry {
    pub fn all() -> Vec<Box<dyn Check>> {
        inventory::iter::<Box<dyn CheckFactory>>
            .map(|f| f.create())
            .collect()
    }
}
```

**Each branch's new check (e.g., `ssrf.rs`):**

```rust
use inventory::submit;
use super::{Check, CheckFactory};

pub struct SsrfCheck { /* fields */ }

impl Check for SsrfCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> { /* ... */ }
}

// AUTO-REGISTER: No mod.rs edit needed!
struct SsrfFactory;
impl CheckFactory for SsrfFactory {
    fn name(&self) -> &'static str { "ssrf" }
    fn create(&self) -> Box<dyn Check> { Box::new(SsrfCheck::new()) }
}
submit!(Box::new(SsrfFactory) as Box<dyn CheckFactory>);
```

**Benefit:** 7 branches each add `pub mod ssrf;` and `pub mod header_injection;` etc. in `mod.rs`, but **no line conflicts** because each branch's block is disjoint.

**Trade-off:** Slight runtime overhead (inventory iteration vs. direct instantiation), but negligible for a WAF engine.

---

## Worktree & PR Workflow

### Step 1: Create 7 Worktrees (from main)

```bash
#!/bin/bash
# scripts/create-worktrees.sh

MAIN_REPO="/Users/admin/lab/mini-waf"
FEATURES=(
  "fr014:sqli-scanner-v2"
  "fr015:ssrf-detection"
  "fr016:header-injection"
  "fr017:brute-force-lock"
  "fr018:body-size-abuse"
  "fr019:proto-smuggling"
  "fr020:crypto-downgrade"
)

# Ensure main is checked out + up-to-date
cd "$MAIN_REPO"
git fetch origin main
git checkout main
git pull origin main

# Create worktree for each feature
for feature in "${FEATURES[@]}"; do
  IFS=':' read -r fnum fslug <<< "$feature"
  BRANCH="feat/${fnum}-${fslug}"
  WORKTREE_PATH="../mini-waf-${fnum}"

  # Clean up old worktree if exists
  git worktree remove "$WORKTREE_PATH" 2>/dev/null || true

  # Create new worktree, branched from main
  git worktree add -b "$BRANCH" "$WORKTREE_PATH" origin/main
  
  echo "Created worktree: $WORKTREE_PATH → $BRANCH"
done

echo "All 7 worktrees created. Each can now develop independently."
```

### Step 2: Isolate Build Environment per Worktree

**File:** `scripts/setup-worktree-env.sh`

```bash
#!/bin/bash
# Sets CARGO_TARGET_DIR per worktree to avoid cache contention

WORKTREE_PATH="$1"
if [ -z "$WORKTREE_PATH" ]; then
  echo "Usage: $0 /path/to/worktree"
  exit 1
fi

# Each worktree gets its own target dir
export CARGO_TARGET_DIR="${WORKTREE_PATH}/target"
export CARGO_INCREMENTAL=1  # Faster rebuilds

# Source this in each worktree's shell:
# source ../scripts/setup-worktree-env.sh ../mini-waf-fr014

echo "Set CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
```

**Usage in each worktree:**

```bash
cd ../mini-waf-fr014
source ../mini-waf/scripts/setup-worktree-env.sh .
cargo build  # Uses ./target, not shared
cargo test
```

### Step 3: File Conflict Map

**Shared files that 7 branches will edit:**

| File | Issue | Mitigation |
|------|-------|-----------|
| `crates/waf-engine/src/checks/mod.rs` | Add `pub mod <check>;` per branch | Use inventory! macro; each branch's block disjoint |
| `crates/waf-common/src/types.rs` (DefenseConfig) | Add new enum variant per check | Extend enum once in phase-0; branches only add check impl, not enum |
| `Cargo.lock` | Diverges if deps added | DON'T commit Cargo.lock to feature branches; let CI regenerate |

**Resolution:**

1. **Phase-0 PR (merged FIRST):** Add `inventory!` macro framework + extend `DefenseConfig` enum with all 7 new variants at once. Merge to main.
2. **Phase-1..7 PRs (parallel):** Each branch only adds `pub mod <check>;` in mod.rs and implements Check. No enum edits. Rebase onto updated main.
3. **Merge strategy:** Squash each PR individually; rebase subsequent siblings after each merge.

### Step 4: Commit & Squash per Worktree

```bash
#!/bin/bash
# In each worktree: scripts/finalize-branch.sh

BRANCH=$(git rev-parse --abbrev-ref HEAD)
WORKTREE_PATH=$(pwd)

# Compile check
cargo check -p waf-engine

# Run tests scoped to this check
cargo test -p waf-engine --lib checks::

# Squash: rebase onto main (auto-squash if WIP commits)
git rebase -i origin/main --autosquash

# Force push to feature branch (safe: only you're on this worktree)
git push origin "$BRANCH" --force-with-lease
```

### Step 5: Batch Open PRs via gh

```bash
#!/bin/bash
# scripts/batch-open-prs.sh (run from main repo)

MAIN_REPO="/Users/admin/lab/mini-waf"
FEATURES=(
  "fr014:sqli-scanner-v2"
  "fr015:ssrf-detection"
  "fr016:header-injection"
  "fr017:brute-force-lock"
  "fr018:body-size-abuse"
  "fr019:proto-smuggling"
  "fr020:crypto-downgrade"
)

cd "$MAIN_REPO"

for feature in "${FEATURES[@]}"; do
  IFS=':' read -r fnum fslug <<< "$feature"
  BRANCH="feat/${fnum}-${fslug}"

  # Ensure branch is pushed
  git push origin "$BRANCH" --force-with-lease 2>/dev/null || {
    echo "Skipping $BRANCH: not pushed"
    continue
  }

  # Create PR with auto-filled title/body from commits
  gh pr create \
    --base main \
    --head "$BRANCH" \
    --title "feat($fnum): $fslug" \
    --body "$(cat <<EOF
## Summary
Implement detection check: $fnum ($fslug)

## Testing
- [ ] Cargo test passes
- [ ] Coverage >=90%
- [ ] Manual integration test

## Review Checklist
- [ ] Code follows CLAUDE.md standards
- [ ] No .unwrap() in production code
- [ ] Error handling is explicit
EOF
)" \
    --reviewer "lotus" \
    || echo "PR already exists for $BRANCH"

  sleep 2  # Avoid API rate limit
done

echo "All PRs created. Review at: gh pr list"
```

### Step 6: Rebase Strategy After Each Merge

When PR #1 merges to main, siblings (PRs 2–7) need rebase:

```bash
#!/bin/bash
# scripts/rebase-siblings.sh <merged-branch>

MERGED_BRANCH="$1"  # e.g., "feat/fr014-sqli-scanner-v2"

if [ -z "$MERGED_BRANCH" ]; then
  echo "Usage: $0 feat/fr014-sqli-scanner-v2"
  exit 1
fi

cd /Users/admin/lab/mini-waf

# Fetch latest main
git fetch origin main

# Find all feature branches
for worktree in ../mini-waf-fr*; do
  [ -d "$worktree" ] || continue
  
  BRANCH=$(cd "$worktree" && git rev-parse --abbrev-ref HEAD)
  [ "$BRANCH" = "HEAD" ] && continue
  [ "$BRANCH" = "$MERGED_BRANCH" ] && continue  # Skip merged branch
  
  echo "Rebasing $BRANCH onto origin/main..."
  (
    cd "$worktree"
    git fetch origin main
    git rebase origin/main
    git push origin "$BRANCH" --force-with-lease
  )
done

echo "Rebase complete. Sibling PRs will auto-update in GitHub."
```

### Step 7: Merge PRs (Squash Strategy)

```bash
gh pr merge <PR_NUMBER> \
  --squash \
  --auto \  # Auto-merge when checks pass
  --delete-branch  # Clean up remote branch
```

---

## Pitfall Mitigations

| Pitfall | Problem | Mitigation |
|---------|---------|-----------|
| **Shared Cargo.lock** | Each worktree's `cargo build` writes different Cargo.lock entries if deps differ | **Don't commit Cargo.lock to feature branches.** CI regenerates on main. |
| **target/ contention** | 7 worktrees all writing to `./target` causes `lock(target/.cargo-lock)` contention | **Set `CARGO_TARGET_DIR=<worktree>/target` per worktree.** No sharing. |
| **Git index conflicts** | mod.rs has 7 parallel edits (each branch adds `pub mod xyzcheck;`) | **inventory! macro eliminates line conflicts.** Each block is disjoint. |
| **Rebase cascade** | Merge PR#1 → 6 siblings all need rebase | **Automate with `rebase-siblings.sh`.** Run after each merge. |
| **Stale PR checks** | PR opened, main advances, PR checks outdated | **GitHub auto-reruns checks when base updates.** No action needed. |
| **Cargo cache poisoning** | If branches run different feature flags, cache may corrupt | **Use `CARGO_INCREMENTAL=0` per worktree if paranoid.** Small perf cost. |

---

## Implementation Checklist

- [ ] **Phase-0:** Add `inventory!` macro to `crates/waf-engine/Cargo.toml` (`inventory = "0.1"`), create mod.rs framework, open PR, merge to main
- [ ] **Phase-1:** Run `scripts/create-worktrees.sh` to spin up 7 worktrees
- [ ] **Phase-2:** In each worktree, implement check (xss, dir_traversal, scanner, ssrf, header_injection, brute_force, body_abuse)
- [ ] **Phase-3:** In each worktree, run `source ../mini-waf/scripts/setup-worktree-env.sh . && cargo test -p waf-engine`
- [ ] **Phase-4:** Squash commits via `scripts/finalize-branch.sh` in each worktree
- [ ] **Phase-5:** Push all branches, then `scripts/batch-open-prs.sh` to open 7 PRs at once
- [ ] **Phase-6:** As each PR merges, run `scripts/rebase-siblings.sh <merged-branch>` to update siblings
- [ ] **Phase-7:** All 7 PRs merged; verify CI passes on main

---

## Unresolved Questions

1. **Inventory macro at compile-time:** Does adding 7 new `submit!()` calls noticeably slow compile time? (Expected: <1s impact; should bench)
2. **DefenseConfig enum extension:** Should all 7 new variants be added in phase-0, or lazily per branch? (Recommend phase-0 for clarity)
3. **Coverage gate per-crate:** Should waf-engine enforce 95% vs. 90%? (Spec defaults to 90%; may need adjustment post-implementation)
4. **Worktree cleanup:** Should `scripts/create-worktrees.sh` auto-prune completed worktrees, or manual `git worktree remove`? (Recommend manual; safer)

---

## Sources

- [cargo-llvm-cov GitHub](https://github.com/taiki-e/cargo-llvm-cov)
- [cargo-llvm-cov crates.io](https://crates.io/crates/cargo-llvm-cov)
- [Git Worktree Docs](https://git-scm.com/docs/git-worktree)
- [gh pr create](https://cli.github.com/manual/gh_pr_create)
- [cargo-worktree tool (Rust Forum)](https://users.rust-lang.org/t/tool-cargo-worktree-fix-build-isolation-in-git-worktrees/139192)
- [CARGO_TARGET_DIR env var](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
- [inventory crate](https://crates.io/crates/inventory)
