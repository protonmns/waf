#!/usr/bin/env bash
# setup-worktree-env.sh — pin CARGO_TARGET_DIR to the current worktree's
# own `target/` so parallel worktrees never share build artifacts and the
# main repo's `target/` stays untouched.
#
# Usage: source from inside a worktree:
#   source scripts/setup-worktree-env.sh
#
# (Executing instead of sourcing is a no-op for the parent shell.)
set -euo pipefail

# Detect sourcing vs. execution. When executed, BASH_SOURCE[0] equals $0;
# when sourced, they differ. Bail loudly if executed because exporting in a
# subshell achieves nothing.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "error: source this script (don't execute it)" >&2
    echo "       source scripts/setup-worktree-env.sh" >&2
    exit 2
fi

worktree_root="$(git rev-parse --show-toplevel)"
export CARGO_TARGET_DIR="${worktree_root}/target"
echo "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
