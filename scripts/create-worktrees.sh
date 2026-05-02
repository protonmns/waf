#!/usr/bin/env bash
# create-worktrees.sh — provision 7 git worktrees (one per FR PR) so each
# Phase 01..07 can build/test in isolation without colliding on `target/`.
#
# Worktrees are created at ../mini-waf-<slug>/ on branch
# feat/<slug>, branched from origin/main. Existing worktrees with the same
# path are removed first (idempotent re-runs).
#
# Companion: source `scripts/setup-worktree-env.sh` from inside each
# worktree to pin `CARGO_TARGET_DIR` to the worktree's own `target/`.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
PARENT_DIR="$(dirname "$REPO_ROOT")"

# Slug list — branch names match the plan.md Phases table.
SLUGS=(
    "fr-014-xss-json-walk"
    "fr-015-path-traversal-recursive"
    "fr-016-ssrf-detection"
    "fr-017-header-injection"
    "fr-019-scanner-recon"
    "fr-020-body-abuse"
    "fr-018-brute-force"
)

# Fetch latest origin/main so we branch from a fresh tip.
git fetch origin main --quiet

for slug in "${SLUGS[@]}"; do
    branch="feat/${slug}"
    worktree_path="${PARENT_DIR}/mini-waf-${slug}"

    # Idempotent removal: ignore failure when the worktree doesn't exist.
    git worktree remove --force "${worktree_path}" 2>/dev/null || true

    # Reuse an existing branch if it already exists locally; otherwise
    # branch from origin/main.
    if git show-ref --verify --quiet "refs/heads/${branch}"; then
        git worktree add "${worktree_path}" "${branch}"
    else
        git worktree add -b "${branch}" "${worktree_path}" origin/main
    fi

    echo "worktree ready: ${worktree_path} (branch ${branch})"
done

echo
echo "all 7 worktrees created. cd into one and 'source scripts/setup-worktree-env.sh' to isolate target/."
