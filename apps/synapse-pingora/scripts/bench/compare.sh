#!/usr/bin/env bash
# Compare two k6 result summaries produced by run.sh.
# Highlights regressions > 5% on p95 / p99 latency and RPS.
#
# Usage:
#   ./scripts/bench/compare.sh <baseline.summary.json> <candidate.summary.json>

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <baseline.summary.json> <candidate.summary.json>" >&2
  exit 2
fi

BASE="$1"
CAND="$2"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. brew install jq" >&2
  exit 1
fi

extract() {
  jq -r '
    [
      (.metrics.http_req_duration.values["p(50)"] // 0),
      (.metrics.http_req_duration.values["p(95)"] // 0),
      (.metrics.http_req_duration.values["p(99)"] // 0),
      (.metrics.http_reqs.values.rate // 0),
      (.metrics.http_req_failed.values.rate // 0)
    ] | @tsv
  ' "$1"
}

read -r B_P50 B_P95 B_P99 B_RPS B_FAIL <<< "$(extract "$BASE")"
read -r C_P50 C_P95 C_P99 C_RPS C_FAIL <<< "$(extract "$CAND")"

pct() {
  awk -v a="$1" -v b="$2" 'BEGIN { if (a == 0) { print "?"; exit } printf "%+.1f%%", ((b - a) / a) * 100 }'
}

flag() {
  # Args: label, baseline, candidate, direction (lower_is_better|higher_is_better), threshold_pct
  local label="$1" base="$2" cand="$3" dir="$4" thr="$5"
  local delta_pct
  delta_pct=$(awk -v a="$base" -v b="$cand" 'BEGIN { if (a == 0) { print 0; exit } print ((b - a) / a) * 100 }')
  local abs_delta
  abs_delta=$(awk -v d="$delta_pct" 'BEGIN { printf "%.2f", (d < 0 ? -d : d) }')
  local is_regression=0
  if [[ "$dir" == "lower_is_better" ]]; then
    is_regression=$(awk -v d="$delta_pct" -v t="$thr" 'BEGIN { print (d > t) ? 1 : 0 }')
  else
    is_regression=$(awk -v d="$delta_pct" -v t="$thr" 'BEGIN { print (d < -t) ? 1 : 0 }')
  fi
  local marker="     "
  if [[ "$is_regression" == "1" ]]; then
    marker=" !!! "
  fi
  printf "%s %-10s baseline=%-10s candidate=%-10s  delta=%s\n" \
    "$marker" "$label" "$base" "$cand" "$(pct "$base" "$cand")"
}

echo "baseline:  $BASE"
echo "candidate: $CAND"
echo ""
flag "p50 (ms)"  "$B_P50"  "$C_P50"  lower_is_better  5
flag "p95 (ms)"  "$B_P95"  "$C_P95"  lower_is_better  5
flag "p99 (ms)"  "$B_P99"  "$C_P99"  lower_is_better  5
flag "rps"       "$B_RPS"  "$C_RPS"  higher_is_better 5
flag "fail_rate" "$B_FAIL" "$C_FAIL" lower_is_better  1
