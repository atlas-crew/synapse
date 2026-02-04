#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
fd-lifecycle.sh --pid <pid> [options]

Options:
  --pid <pid>           Target process ID (required)
  --duration <sec>      Sample duration in seconds (default: 0 = single sample)
  --interval <sec>      Sample interval in seconds (default: 1)
  --output <file>       Write CSV samples (timestamp,fd_count) to file
  --baseline <file>     Write baseline FD count to file
  --max-drift <count>   Exit non-zero if max drift exceeds count
  --repeat <n>          Repeat a command N times (default: 1)
  --cmd <command>       Command to run each repeat iteration (optional)
  --help                Show this help

Notes:
- Uses /proc/<pid>/fd if available, otherwise falls back to lsof.
- For repeat mode, the command runs before each sample.
USAGE
}

PID=""
DURATION=0
INTERVAL=1
OUTPUT=""
BASELINE=""
MAX_DRIFT=""
REPEAT=1
CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid)
      PID="${2:-}"
      shift 2
      ;;
    --duration)
      DURATION="${2:-0}"
      shift 2
      ;;
    --interval)
      INTERVAL="${2:-1}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    --baseline)
      BASELINE="${2:-}"
      shift 2
      ;;
    --max-drift)
      MAX_DRIFT="${2:-}"
      shift 2
      ;;
    --repeat)
      REPEAT="${2:-1}"
      shift 2
      ;;
    --cmd)
      CMD="${2:-}"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$PID" ]]; then
  echo "Missing --pid" >&2
  usage
  exit 2
fi

if [[ ! "$PID" =~ ^[0-9]+$ ]]; then
  echo "--pid must be numeric" >&2
  exit 2
fi

fd_count() {
  if [[ -d "/proc/$PID/fd" ]]; then
    ls -1 "/proc/$PID/fd" 2>/dev/null | wc -l | tr -d ' '
    return
  fi

  if command -v lsof >/dev/null 2>&1; then
    lsof -p "$PID" -Fn 2>/dev/null | sed -n 's/^n//p' | wc -l | tr -d ' '
    return
  fi

  echo "No /proc/<pid>/fd and lsof missing; cannot count FDs" >&2
  exit 3
}

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

record_sample() {
  local ts count line
  ts="$(timestamp)"
  count="$(fd_count)"
  line="${ts},${count}"
  if [[ -n "$OUTPUT" ]]; then
    echo "$line" >> "$OUTPUT"
  else
    echo "$line"
  fi
  echo "$count"
}

if [[ -n "$OUTPUT" ]]; then
  echo "timestamp,fd_count" > "$OUTPUT"
fi

baseline="$(fd_count)"
if [[ -n "$BASELINE" ]]; then
  echo "$baseline" > "$BASELINE"
fi

min="$baseline"
max="$baseline"

run_cmd() {
  if [[ -n "$CMD" ]]; then
    bash -lc "$CMD"
  fi
}

start_epoch="$(date +%s)"
end_epoch=$((start_epoch + DURATION))

iteration=0
while :; do
  iteration=$((iteration + 1))
  run_cmd
  current="$(record_sample)"
  if [[ "$current" -lt "$min" ]]; then
    min="$current"
  fi
  if [[ "$current" -gt "$max" ]]; then
    max="$current"
  fi

  if [[ "$DURATION" -eq 0 ]]; then
    if [[ "$iteration" -ge "$REPEAT" ]]; then
      break
    fi
  else
    now_epoch="$(date +%s)"
    if [[ "$now_epoch" -ge "$end_epoch" ]]; then
      break
    fi
  fi

  sleep "$INTERVAL"
done

drift=$((max - baseline))
echo "baseline=${baseline} min=${min} max=${max} drift=${drift}"

if [[ -n "$MAX_DRIFT" && "$drift" -gt "$MAX_DRIFT" ]]; then
  echo "FD drift exceeded: ${drift} > ${MAX_DRIFT}" >&2
  exit 4
fi
