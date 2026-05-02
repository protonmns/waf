#!/usr/bin/env bash
# coverage-gate.sh — enforce a line-coverage threshold against
# `cargo llvm-cov --summary-only` output.
#
# `cargo-llvm-cov` 0.8.5 has an upstream bug where `--fail-under-lines`
# is silently ignored when combined with `--ignore-filename-regex`; we
# parse the TOTAL line ourselves to avoid that pitfall (see plan §Sec1).
#
# Usage:
#   coverage-gate.sh <summary_file> <threshold_pct>
#
# Inputs:
#   summary_file  — text capture of `cargo llvm-cov --summary-only`
#                   (the table that ends with a `TOTAL ...` row)
#   threshold_pct — minimum acceptable line coverage (e.g. 90)
#
# Exit codes:
#   0  threshold met
#   1  threshold not met
#   2  usage / parse error
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <summary_file> <threshold_pct>" >&2
    exit 2
fi

summary_file="$1"
threshold="$2"

if [[ ! -f "$summary_file" ]]; then
    echo "error: summary file not found: $summary_file" >&2
    exit 2
fi

# `cargo llvm-cov --summary-only` writes a fixed column layout. On the
# TOTAL row, the 10th whitespace-separated field is the "Lines Cover %":
#   $1=TOTAL  $2=Regions  $3=MissedRegions  $4=RegionsCover%
#   $5=Functions  $6=MissedFunctions  $7=Executed%
#   $8=Lines  $9=MissedLines  $10=LinesCover%
#   $11=Branches  $12=MissedBranches  $13=BranchesCover%
pct=$(awk '/^TOTAL/ {
    val = $10
    gsub("%", "", val)
    print val
    exit
}' "$summary_file")

if [[ -z "$pct" ]]; then
    echo "error: could not parse TOTAL line from $summary_file" >&2
    exit 2
fi

# Numeric compare via awk so we don't need bc/python on minimal images.
awk -v p="$pct" -v t="$threshold" 'BEGIN { exit (p+0 < t+0) }' && status=0 || status=1

if [[ "$status" -eq 0 ]]; then
    echo "coverage gate ok: ${pct}% >= ${threshold}%"
    exit 0
fi

echo "::error::coverage ${pct}% below ${threshold}% gate" >&2
exit 1
