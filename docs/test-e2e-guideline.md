# Nightly E2E Suite

Drives two nightly test workflows:

1. **[`.github/workflows/nightly-e2e.yml`](../../.github/workflows/nightly-e2e.yml)** — Shell-based integration suites
   - Exercises rule engine, gateway proxy, admin API, and cluster end-to-end
   - Spins up Docker Compose stacks (single-node + 3-node cluster)
   - Each suite emits **JUnit XML**, **JSON**, and **Markdown** artefacts
   - Aggregated report published to workflow summary and GitHub Checks

2. **[`.github/workflows/ddos-soak.yml`](../../.github/workflows/ddos-soak.yml)** — FR-005 DDoS soak test (separate)
   - Memory/leak surveillance: 5+ min sustained load at 1K+ RPS
   - Verifies ban table growth bounded, RSS drift <5%, no panics
   - Runs nightly on schedule; also triggered by `workflow_dispatch` for manual PR validation
   - See [ddos-protection.md](./ddos-protection.md) for detailed test suite

The goal is to catch regressions in main user-facing surfaces every night before they ship.

---

## Layout

```
tests/e2e/
├── lib.sh                       # shared helpers (assert_*, JUnit/JSON writers, wait_health, etc.)
├── configs/e2e.toml             # PRX-WAF config used by the single-node stack
├── docker-compose.e2e.yml       # postgres + go-httpbin + prx-waf single-node stack
├── cluster-override.yml         # docker-compose override that injects ADMIN_PASSWORD into all 3 cluster nodes
├── run-rules-engine.sh          # verifies every rule category in `rules/`
├── run-gateway.sh               # crates/gateway proxy behaviour
├── run-api.sh                   # crates/waf-api admin endpoints
├── run-cluster.sh               # crates/waf-cluster (election, replication, mTLS)
├── render-report.sh             # aggregates per-suite JSON → Markdown + HTML
└── out/                         # per-suite results.json / junit.xml / summary.md  (gitignored)
```

Each `run-*.sh` is **self-contained** — sources `lib.sh`, calls `e2e_init`, runs
its assertions, calls `e2e_finalize`. They never invoke each other and can run
in parallel (the workflow does exactly that).

---

## Running locally

### Prerequisites

- Rust toolchain (stable) — `cargo build` produces the `prx-waf` binary
- Docker / Docker Compose (`docker compose` v2 preferred; the helper
  `detect_compose` in `lib.sh` also supports `docker-compose` v1 and
  `podman-compose`)
- `curl` (used everywhere)

### One-shot: build + run a single suite

```bash
# 1. Build the binary (Dockerfile.prebuilt copies it into the WAF image)
cargo build --release -p prx-waf

# 2. Stub directories so the prebuilt Dockerfile has something to COPY
mkdir -p data web/admin-panel/dist

# 3. Start the stack (postgres + go-httpbin + prx-waf)
docker compose -f tests/e2e/docker-compose.e2e.yml up -d --build

# 4. Run any single-node suite
bash tests/e2e/run-rules-engine.sh
bash tests/e2e/run-gateway.sh
bash tests/e2e/run-api.sh

# 5. Cluster suite (uses tests/docker-compose.cluster.yml + cluster-override.yml)
bash tests/e2e/run-cluster.sh

# 6. Aggregate every suite under tests/e2e/out/ into a single report
bash tests/e2e/render-report.sh tests/e2e/out tests/e2e/out/aggregated
open tests/e2e/out/aggregated/report.html        # macOS
xdg-open tests/e2e/out/aggregated/report.html    # Linux

# 7. Clean up
docker compose -f tests/e2e/docker-compose.e2e.yml down -v
```

### Useful environment overrides

| Variable        | Default                       | Purpose                                                |
| --------------- | ----------------------------- | ------------------------------------------------------ |
| `E2E_OUT_DIR`   | `tests/e2e/out/<suite>`       | Redirect a suite's artefacts somewhere else           |
| `ADMIN_USER`    | `admin`                       | Admin login used by the API/Rules suites              |
| `ADMIN_PASS`    | `admin123`                    | Matches `ADMIN_PASSWORD` env in `docker-compose.e2e.yml` |
| `COMPOSE_CMD`   | auto-detected                 | Force a specific compose binary (e.g. `podman-compose`) |

### When something fails locally

1. Look at `tests/e2e/out/<suite>/summary.md` — it lists every test and why it
   failed.
2. Tail the WAF container: `docker compose -f tests/e2e/docker-compose.e2e.yml logs --tail=300 prx-waf`.
3. Reproduce the curl call manually — every `[FAIL]` line in the suite output
   already echoes the exact `curl ...` invocation that produced it.

---

## On-GitHub viewing

After the nightly run completes the report is reachable from three places:

- **Workflow run page** — Markdown summary at the top of the page (every suite
  job + the aggregated `report` job all write to `$GITHUB_STEP_SUMMARY`).
- **Checks tab** — `mikepenz/action-junit-report` publishes per-test pass/fail
  with stack traces directly on the commit / PR.
- **Artifacts** — `e2e-report` artifact contains a self-contained `report.html`
  for sharing or archiving. Per-suite JSON / JUnit are uploaded as
  `e2e-rules-engine`, `e2e-gateway`, `e2e-api`, `e2e-cluster`.

Manual trigger:

```bash
# Run all suites
gh workflow run nightly-e2e.yml --ref feature/e2e-test

# Run only one or two suites (comma-separated, no spaces)
gh workflow run nightly-e2e.yml --ref feature/e2e-test \
  -f suites=rules-engine,gateway
```

---

## Architecture cheat-sheet

```
                    ┌──────────────────────┐
 GitHub schedule ──▶│  build (ubuntu-22.04)│  produces target/release/prx-waf
                    │  → prx-waf-bin       │  (artifact, glibc-compat verified)
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┬──────────────┐
                ▼              ▼              ▼              ▼
        rules-engine job   gateway job    waf-api job   cluster job
        (single-node       (single-node   (single-node  (3-node stack
         compose stack)    compose stack) compose stack) cluster compose)
                │              │              │              │
                └──────────────┴──────┬───────┴──────────────┘
                                      ▼
                              report job (aggregated)
                                      ▼
                       e2e-report artifact + step summary
```

Each suite job:

1. Downloads the `prx-waf-bin` artifact (no rebuild).
2. Brings up its compose stack.
3. Polls `e2e-prx-waf`'s `docker inspect Health.Status` until `healthy` (max
   ~150s, then dumps logs).
4. Runs its `run-*.sh` (the suite is allowed to fail; we capture artefacts
   first, then assert the suite's exit code in the final step).
5. Always uploads container logs and `tests/e2e/out/<suite>/`.
6. Tears the stack down, regardless of pass/fail.

---

## Adding a new test case

There are three common levels at which you might want to add coverage. Pick
the one that matches what you're verifying.

### Level 1 — A new probe in an EXISTING suite (the 90% case)

You added or changed a rule, an admin endpoint, a header injection check,
etc. and want a one-shot E2E assertion. **You only need to edit one
`run-*.sh` file.**

#### A) `run-rules-engine.sh` — a new attack/CVE probe

Add a single `expect_block` call in the appropriate category section. The
helper already handles diagnostics (extracts `rule_name` from the WAF block
page when the request was NOT blocked).

```bash
# OWASP CRS — SQLi
expect_block "sqli.boolean" -G --data-urlencode "q=1' OR '1'='1" "$PROXY/get"
#            ^                                                    ^
#            unique test id (stable; do not rename casually)      target URL
#            (becomes "block.sqli.boolean" in JUnit/JSON)
```

For a NEGATIVE control (request must be allowed through):

```bash
assert_http_status "control.benign-image" "200" "$PROXY/image/png"
```

If you add a brand-new category (e.g. `cve-2026-12345`), append it to the
`CATEGORIES=( ... )` array near the top so the registry presence check picks
it up too.

#### B) `run-gateway.sh` — a new proxy/cache/header behaviour

```bash
# Forward + status passthrough (no WAF rule must fire)
assert_http_status "passthrough.302" "302" "$PROXY/redirect-to?url=/get"

# Body content assertion: pull the response and use assert_contains
RESP=$(http_get "$PROXY/get")
assert_contains "forward.echoes-host" "e2e.local" "$RESP"
```

Use `http_get` (timeout-bounded curl) for body inspection and
`assert_http_status` for status-only checks. Avoid bare `curl ... | grep`
chains — they break under `set -euo pipefail` if grep returns 1.

#### C) `run-api.sh` — a new admin endpoint

The login dance + JWT plumbing is already done at the top of the script;
your test just needs to reuse the `AUTH=( -H "Authorization: Bearer $TOKEN" )`
array.

```bash
# GET (status-only)
assert_http_status "rules.list" "200" "${AUTH[@]}" "$ADMIN/api/rules"

# POST + body inspection
RESP=$(http_get -X POST "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-test","pattern":"^/admin"}' \
    "$ADMIN/api/block-urls")
assert_contains "block-urls.create" '"success":true' "$RESP"
```

#### D) `run-cluster.sh` — a new cluster-only behaviour

This suite is thicker because it has to spin up 3 nodes, wait for an
election, then assert. Reuse the existing helpers (`fetch_status`,
`get_role`, `wait_for_role`) rather than rolling your own — they already
log HTTP code / body to stderr so they don't pollute `$(...)` capture.

### Level 2 — A new suite (a new top-level test file)

Use this when you're exercising a major surface that doesn't fit any
existing suite (e.g. WebSocket, Lua/Rhai plugin engine, mTLS pinning).

#### Step 1 — create `tests/e2e/run-<name>.sh`

```bash
#!/usr/bin/env bash
# Brief description of what this suite verifies and any prerequisites.
#
# Pre-requisites:
#   - tests/e2e/docker-compose.e2e.yml is running
#
# Outputs: tests/e2e/out/<name>/{results.json,junit.xml,summary.md}

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

PROXY="http://localhost:16880"
ADMIN="http://localhost:16827"

e2e_init "<name>"   # name of the suite — must match the dir under out/

# Optional: gate everything on the WAF being healthy
if ! wait_health "WAF API" "$ADMIN/health" 90; then
    fail "waf.health" "API never became healthy"
    e2e_finalize || true
    exit 1
fi
pass "waf.health"

# ── Your assertions ─────────────────────────────────────────────────────────
assert_http_status "feature.smoke" "200" "$ADMIN/api/your-endpoint"

e2e_finalize        # writes JUnit + JSON + Markdown summary,
                    # exits 1 if any test failed
```

Then make it executable:

```bash
chmod +x tests/e2e/run-<name>.sh
```

#### Step 2 — add a job to `.github/workflows/nightly-e2e.yml`

Copy the `rules-engine:` job (`.github/workflows/nightly-e2e.yml` lines
~80-140) verbatim and tweak:

- `name: <Capitalised> E2E`
- `if: ${{ inputs.suites == '' || contains(inputs.suites, '<name>') }}`
- `Run <name> suite` step → `bash tests/e2e/run-<name>.sh`
- `Upload suite artefacts` → `name: e2e-<name>`, `path: tests/e2e/out/<name>`
- Update the `suites` input description at the top of the file so
  `workflow_dispatch` documents the new value.

#### Step 3 — wire the new suite into the aggregated report

`.github/workflows/nightly-e2e.yml` has a `report:` job near the bottom that
downloads every per-suite artifact. Add your new artifact name to its
`needs:` list and to the artifact-download matrix. `render-report.sh` itself
takes a directory and walks every `*/results.json` underneath, so no script
changes are required as long as your suite drops `results.json` into
`tests/e2e/out/<name>/`.

#### Step 4 — list the new suite in the dispatch help text

Update the `inputs.suites` description at the top of the workflow:

```yaml
description: "Comma-separated list of suites to run (rules-engine,gateway,waf-api,cluster,<name>) — empty = all"
```

…and add a row to the `Layout` section of this README.

### Level 3 — A new helper in `lib.sh`

If two or more suites need the same primitive (e.g. an OAuth flow, a
multipart upload, a polling-with-backoff loop), promote it to `lib.sh` so
every suite can share it. Conventions:

- Name it `assert_*` if it records pass/fail, otherwise `e2e_*` for
  lifecycle helpers or a plain verb (`http_get`, `wait_health`) for utilities.
- ALWAYS go through `pass`/`fail` so the test shows up in `results.json` /
  `junit.xml`. Returning a non-zero exit code from inside an assertion is
  fatal because every script runs under `set -euo pipefail`.
- Keep helpers stdin-friendly when dealing with potentially large strings —
  `awk -v s="$BIG"` will hit `ARG_MAX` (this is a bug we already burned a
  day on; see the comment in `run-rules-engine.sh` about the registry size).

---

## Conventions and gotchas

- **Test names are STABLE identifiers.** They become entries in
  `junit.xml` and feed the Checks tab; renaming them breaks history. When in
  doubt, ADD a new test rather than renaming an old one.
- **`set -euo pipefail` is non-negotiable.** Every assertion helper has
  been written so that `grep` / `awk` returning non-zero on no-match
  doesn't kill the suite mid-run. Mirror that pattern when writing new
  helpers (use `awk gsub` or guard with `|| true`).
- **Curl always uses `--max-time 10`** (and `-k` to accept the WAF's
  self-signed cert). Tests should be fast and never block on a hanging
  upstream.
- **The benign control test exists for a reason.** Always pair attack
  probes with at least one negative control (`assert_http_status "control.*"
  "200" ...`). False positives are silent killers — they make the suite
  look healthy while the WAF blocks every legitimate request in production.
- **Diagnostics > pass/fail.** Every existing helper already echoes the
  exact `curl` invocation it ran on failure. Continue that habit when
  adding new helpers — debugging a CI run by guessing what curl did is
  miserable.
- **Don't `sleep` blindly to wait for a service.** Use `wait_health` (it
  polls a real readiness URL and returns as soon as the service answers).
- **Per-suite `out/` is gitignored.** The workflow uploads it as an
  artifact, so don't commit the artefacts even if they look interesting —
  link to the GH run instead.

---

## Linting

```bash
shellcheck tests/e2e/*.sh         # shell linter
```

The CI runs the same check as part of the workflow. Keep
`# shellcheck source=...` directives accurate when adding new sourced
files so shellcheck can follow them.
