# HTTP Benchmark Harness

End-to-end HTTP benchmark rig for Synapse. Drives real HTTP traffic through
the full proxy pipeline — the Synapse server process, its upstream selection,
the WAF detection path, and the response path — and records k6 summaries
that can be compared across runs or across machines.

Distinct from the Criterion suite (`benches/*.rs`, documented in
[REPRODUCING_BENCHMARKS.md](REPRODUCING_BENCHMARKS.md)), which measures
in-process function-level cost. Use the Criterion suite for micro-optimization
work; use this harness when the question is "what throughput/latency does
Synapse actually deliver over a socket?"

## When to use which

| Question | Tool |
| --- | --- |
| Did this PR regress `evaluate_rule()` by > 5%? | Criterion (`cargo bench --bench detection`) |
| Does Synapse still hold p95 < 2ms at 50K rps? | HTTP harness |
| Is the new rule compiler faster in isolation? | Criterion |
| Does the new rule compiler change end-to-end throughput? | HTTP harness |
| How much CPU does the proxy hot path cost? | Either, but HTTP + `perf` is more honest |

## Components

All under `scripts/bench/`:

- `upstream.conf` — self-contained nginx config. Null backend that answers
  every path with `{"ok":true}` on `127.0.0.1:8080`. `reuseport`,
  `keepalive_requests 10000`, access log off so nginx never becomes the
  bottleneck.
- `start-upstream.sh` — runs `nginx -t` first, then execs nginx in the
  foreground with `daemon off`. Ctrl-C stops it.
- `run.sh` — the orchestrator. Two preflight checks (target reachability +
  upstream-alive-through-Synapse), a 30s warmup, then the measurement
  phase. Writes a summary JSON + raw stream to `benches/results/`.
- `compare.sh` — diffs two result summaries. Flags > 5% regressions on
  latency and RPS, > 1% regressions on fail_rate.

The k6 workloads in `benches/k6/` both honor the `TARGET_URL` env var:

- `scenarios.js` — realistic request mix driven from
  `benches/scenarios.json` (E-comm, GraphQL, Healthcare, Bulk, Attack).
  Default rate 100 rps; good for functional verification more than
  throughput.
- `high_load.js` — fixed-rate load, 5000 rps default, rotates a small
  endpoint set. Use this for throughput/latency measurement.

## Prerequisites

- `k6` — `brew install k6` (macOS) or see [k6 install docs](https://k6.io/docs/getting-started/installation/).
- `nginx` — `brew install nginx` or `apt-get install nginx-light`.
- `jq` — for the pretty summary line run.sh prints and for `compare.sh`.
- `cargo` + the `release` build of Synapse.

## Single-host run (quick regression check)

```bash
cd apps/synapse-pingora

# Terminal 1 — null backend
scripts/bench/start-upstream.sh

# Terminal 2 — Synapse on the bench config
cargo run --release -- --config config.bench.yaml

# Terminal 3 — drive load
BENCH_TAG=main-baseline ./scripts/bench/run.sh high_load --duration 2m
```

All three processes on one box. Measures Synapse's CPU cost in isolation
(no network hop). Good for tracking relative change between commits;
not useful for absolute "how fast is Synapse" numbers because the
load generator and SUT share CPU and memory bandwidth.

## Two-host run (Thunderbolt bridge)

The intended setup for honest numbers. One machine runs Synapse + null
backend (the SUT), the other machine runs k6 (the load generator).
Connected by a direct Thunderbolt 3/4 cable — ~22 Gbps usable, very
low jitter, no switch or shared network path.

### Bring up the link

On both macs:
1. Connect the Thunderbolt cable.
2. System Settings → Network → Thunderbolt Bridge → configure manually.
3. Pick a `/24` neither machine routes already, e.g. `10.10.0.0/24`.
4. SUT = `10.10.0.2/24`. Load generator = `10.10.0.1/24`. No gateway.
5. Bump MTU to 9000 on both ends (jumbo frames):
   `sudo ifconfig bridge0 mtu 9000`.
6. Confirm: `ping -c 3 10.10.0.2` from the load gen. Should be sub-ms.

On Linux:
```bash
sudo modprobe thunderbolt-net  # usually automatic
sudo ip link set dev thunderbolt0 up
sudo ip addr add 10.10.0.1/24 dev thunderbolt0
sudo ip link set dev thunderbolt0 mtu 9000
```

### SUT side

Edit `config.bench.yaml` so Synapse binds to the bridge:

```yaml
server:
  listen: "10.10.0.2:6190"   # was 127.0.0.1:6190
```

Upstream stays at `127.0.0.1:8080` — the null backend lives on the
same box as Synapse; that's deliberate. It isolates "what does Synapse
cost" from "what does a TB roundtrip cost."

```bash
# Terminal 1
scripts/bench/start-upstream.sh

# Terminal 2
cargo run --release -- --config config.bench.yaml
```

### Load generator side

```bash
export TARGET_URL=http://10.10.0.2:6190

BENCH_TAG=main-baseline   ./scripts/bench/run.sh high_load --duration 2m
# Make your change on the SUT, rebuild, restart Synapse, then:
BENCH_TAG=my-change       ./scripts/bench/run.sh high_load --duration 2m

# Compare
./scripts/bench/compare.sh \
  benches/results/<ts>_main-baseline_high_load.summary.json \
  benches/results/<ts>_my-change_high_load.summary.json
```

## What's in a result

Each run writes two files under `benches/results/`:

- `<ts>_<tag>_<workload>.summary.json` — k6's aggregate metrics: p50/p95/p99
  latency, request rate, fail rate, data transferred. This is what `compare.sh`
  reads.
- `<ts>_<tag>_<workload>.raw.json` — one JSON object per request. Large.
  Useful for custom analysis (histogram tails, time-series plots); ignore
  for routine regression work.

The headline `run.sh` prints at the end is `jq`'d from the summary:
```
p50=1.8ms p95=4.1ms p99=9.3ms rps=4987.2 fail=0
```

## Interpreting results honestly

- **`fail > 0.01`** means the run didn't measure what you think it did. Root
  cause it (usually: upstream died, Synapse OOM'd, you're ratelimited).
  Don't accept "p95=0.5ms but fail=0.8" as good news — fast failures are
  fast.
- **`p99 ≫ p95`** usually means GC-like pauses (in Synapse's case:
  ConfigManager reloads, rule-hash recomputes, heartbeat batches
  flushing). The `reload_bench` Criterion suite exercises these paths
  in isolation.
- **Compare `http_req_duration` vs `http_req_waiting`.** The delta is
  connection establishment + network transit. If they're close, Synapse
  CPU dominates; if `http_req_duration` is much larger, network or TLS
  dominates and Synapse is not the bottleneck.
- **Do at least three runs of each condition and eyeball variance.** One
  run is a data point, three is a distribution. If candidate vs. baseline
  delta is less than the run-to-run variance, the difference is noise.

## Known gotchas

- **Don't point Synapse at `httpbin` or any Python/Node backend.** The
  backend becomes the bottleneck and your Synapse numbers are junk.
  Use the provided nginx null backend (or another `return 200` static
  server) or be very explicit about what you're measuring.
- **macOS's default ulimit is low.** `ulimit -n 65536` before a sustained
  run or nginx/Synapse/k6 will all hit FD exhaustion around 10K
  concurrent connections. See [FD_LIFECYCLE.md](FD_LIFECYCLE.md).
- **Don't benchmark debug builds.** `cargo run` defaults to dev profile;
  always pass `--release`. A ~10× latency gap is typical — easy to miss
  if you forget.
- **TLS changes the measurement.** `config.bench.yaml` is HTTP for a
  reason. Adding TLS front of Synapse measures OpenSSL/Rustls as much
  as it measures Synapse. If the question is "does Synapse handle TLS
  fast enough?" that's a different bench.
- **Run-to-run variance > 10% on a laptop is normal.** CPU thermal
  throttling is real and non-deterministic. For publishable numbers,
  pin CPU governor to `performance`, disable turbo, and prefer a
  wall-powered desktop or a Hetzner AX box over a MacBook on battery.

## What this harness deliberately does not do

- **Coordinated-omission correction** — k6 does it at the load-gen side
  via `constant-arrival-rate`. Don't switch to `constant-vus`; it lies
  about tail latency.
- **Multi-machine load generation.** One k6 process per box is the cap.
  If you saturate a single load gen, move to wrk2 with multiple workers
  or run k6 on two boxes and sum results.
- **Automated baseline promotion.** `compare.sh` prints deltas; it does
  not decide what "the baseline" is. Treat one summary file as your
  baseline by convention (e.g., `benches/results/baseline.summary.json`)
  and update it when you ratify a new known-good.
