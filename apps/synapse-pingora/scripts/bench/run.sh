#!/usr/bin/env bash
# Synapse benchmark orchestrator.
#
# Assumes Synapse is already running on TARGET_URL (typically the SUT machine).
# This script is meant to run on the LOAD GENERATOR machine — for a
# Thunderbolt-bridged two-host setup, that is the laptop you set up as
# the non-SUT side. It drives k6 with a warmup phase + measurement phase
# and writes a single JSON result artifact per run.
#
# Usage:
#   TARGET_URL=http://10.10.0.2:6190 ./scripts/bench/run.sh [scenario|high_load] [--duration 60s] [--rate 5000]
#
# Env:
#   TARGET_URL         HTTP base of the SUT. Default http://127.0.0.1:6190.
#   BENCH_WARMUP_SEC   Warmup duration before measurement. Default 30.
#   BENCH_OUT_DIR      Where to write results. Default benches/results.
#   BENCH_TAG          Free-form tag written into the result (e.g. git sha,
#                      'pre-fix', 'post-fix'). Default: git short sha.

set -euo pipefail

# Handle --help before positional parsing so it works regardless of position.
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 0
  fi
done

WORKLOAD="${1:-scenarios}"
shift || true

DURATION="60s"
RATE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --rate)     RATE="$2";     shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

TARGET_URL="${TARGET_URL:-http://127.0.0.1:6190}"
WARMUP="${BENCH_WARMUP_SEC:-30}"
OUT_DIR="${BENCH_OUT_DIR:-benches/results}"
TAG="${BENCH_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

SCRIPT_PATH=""
case "$WORKLOAD" in
  scenarios)  SCRIPT_PATH="benches/k6/scenarios.js" ;;
  high_load)  SCRIPT_PATH="benches/k6/high_load.js" ;;
  *) echo "Unknown workload: $WORKLOAD (expected: scenarios | high_load)" >&2; exit 2 ;;
esac

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 is not installed. Install via 'brew install k6' or see https://k6.io/docs/getting-started/installation/" >&2
  exit 1
fi

# Preflight 1: confirm the target answers at all before we spend time warming up.
if ! curl -fsS -o /dev/null --max-time 3 "$TARGET_URL/healthz" 2>/dev/null \
  && ! curl -fsS -o /dev/null --max-time 3 "$TARGET_URL/" 2>/dev/null; then
  echo "WARN: $TARGET_URL did not answer /healthz or /. Continuing anyway; " \
       "check that Synapse is running and bound to the interface reachable from this host." >&2
fi

# Preflight 2: detect a dead upstream behind Synapse. A request that traverses
# Synapse's proxy path will return 5xx (typically 502) when nothing is
# listening on the configured upstream. Without this check the whole run
# would succeed-but-all-fail, producing a fail_rate≈1.0 summary that looks
# like a regression instead of a missing dependency.
PREFLIGHT_STATUS="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$TARGET_URL/" || echo '000')"
if [[ "$PREFLIGHT_STATUS" == "502" || "$PREFLIGHT_STATUS" == "503" || "$PREFLIGHT_STATUS" == "504" ]]; then
  echo "ERROR: Synapse returned $PREFLIGHT_STATUS for a preflight request." >&2
  echo "       The upstream it proxies to is probably not running." >&2
  echo "       On the SUT, start the null backend:  scripts/bench/start-upstream.sh" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
STEM="${OUT_DIR}/${TS}_${TAG}_${WORKLOAD}"
WARMUP_LOG="${STEM}.warmup.log"
RESULT_SUMMARY="${STEM}.summary.json"
RESULT_RAW="${STEM}.raw.json"

echo "==> Warmup (${WARMUP}s against ${TARGET_URL})"
TARGET_URL="$TARGET_URL" k6 run \
  --quiet \
  --duration "${WARMUP}s" \
  ${RATE:+--env RATE="$RATE"} \
  "$SCRIPT_PATH" \
  >"$WARMUP_LOG" 2>&1 || {
    echo "Warmup failed. See $WARMUP_LOG" >&2
    exit 1
  }

echo "==> Measurement (${DURATION} against ${TARGET_URL})"
TARGET_URL="$TARGET_URL" k6 run \
  --summary-export "$RESULT_SUMMARY" \
  --out "json=${RESULT_RAW}" \
  --duration "$DURATION" \
  ${RATE:+--env RATE="$RATE"} \
  "$SCRIPT_PATH"

echo "==> Result: $RESULT_SUMMARY"

# Emit a tight, copy-pasteable headline.
if command -v jq >/dev/null 2>&1; then
  jq -r '
    "p50=\(.metrics.http_req_duration.values["p(50)"] // "?")ms " +
    "p95=\(.metrics.http_req_duration.values["p(95)"] // "?")ms " +
    "p99=\(.metrics.http_req_duration.values["p(99)"] // "?")ms " +
    "rps=\(.metrics.http_reqs.values.rate // "?") " +
    "fail=\(.metrics.http_req_failed.values.rate // 0)"
  ' "$RESULT_SUMMARY"
fi
