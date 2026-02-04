# FD Lifecycle Profiling

Goal: detect file descriptor (FD) leaks across connect/disconnect cycles and long-run operation.

## Script

Use `apps/synapse-pingora/scripts/fd-lifecycle.sh`.

Example one-shot:

```bash
apps/synapse-pingora/scripts/fd-lifecycle.sh --pid <PID>
```

Example 60s capture to CSV:

```bash
apps/synapse-pingora/scripts/fd-lifecycle.sh --pid <PID> --duration 60 --interval 1 --output /tmp/fd-samples.csv
```

Example drift gate (fail if drift > 10 FDs):

```bash
apps/synapse-pingora/scripts/fd-lifecycle.sh --pid <PID> --duration 300 --interval 2 --max-drift 10
```

## 100 Connect/Disconnect Cycles

Run your connect/disconnect workload (tunnel shell/logs/diag) and sample during the loop.

Template:

```bash
apps/synapse-pingora/scripts/fd-lifecycle.sh \
  --pid <PID> \
  --repeat 100 \
  --interval 1 \
  --cmd "<connect+disconnect command>"
```

Notes:
- Keep interval >= 1s to avoid sampling overhead.
- If using a custom script, ensure it closes the session each iteration.

## 24h Long-Run

```bash
apps/synapse-pingora/scripts/fd-lifecycle.sh \
  --pid <PID> \
  --duration 86400 \
  --interval 10 \
  --output /tmp/fd-24h.csv \
  --max-drift 10
```

## Monitoring and Alerting

Preferred alert: open FD ratio.

If using `process-exporter` or `node_exporter`:

- Metric: `process_open_fds`
- Metric: `process_max_fds`
- Alert: `process_open_fds / process_max_fds > 0.8` for 5m

If using a custom check, poll `/proc/<pid>/fd` and alert on:
- Sustained growth > 10 over 1h
- Ratio > 80% of `ulimit -n`

## Record Results

Fill in per run:

```
Date:
Host:
PID:
Baseline FD count:
Min FD count:
Max FD count:
Drift:
Workload:
Result:
```
