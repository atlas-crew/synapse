---
title: Benchmarks
---

# Benchmarks

Synapse uses [Criterion.rs](https://bheisler.github.io/criterion.rs/book/) for benchmarking. 19 benchmark files organized across 7 categories, 306 total benchmarks.

## Running Benchmarks

```sh
cd apps/synapse-pingora

# All benchmarks
cargo bench

# Specific suite
cargo bench --bench detection
cargo bench --bench pipeline
```

Criterion generates HTML reports in `target/criterion/`. Open `target/criterion/report/index.html` for an interactive dashboard.

### Build Profile

| Setting | Value |
| --- | --- |
| LTO | thin |
| codegen-units | 1 |
| opt-level | 3 |
| Warm-up | 3 seconds |
| Measurement | 5 seconds |
| Noise threshold | 5% (10% for sustained) |
| Sample size | 100 |

## Benchmark Suites

| # | Suite | File | Category | Benchmarks |
| --- | --- | --- | --- | --- |
| 1 | Detection Engine | `detection.rs` | Core WAF | 29 |
| 2 | Pipeline | `pipeline.rs` | Request chain | 17 |
| 3 | Goblins (DLP) | `goblins.rs` | Data protection | 22 |
| 4 | Contention | `contention.rs` | Concurrency | 60 |
| 5 | Risk Scoring | `risk_scoring.rs` | Threat intel | 18 |
| 6 | Correlation | `correlation.rs` | Threat intel | 14 |
| 7 | API Profiler | `profiler_bench.rs` | Behavioral | 23 |
| 8 | Schema | `schema_bench.rs` | API learning | 19 |
| 9 | Bot Detection | `bot_bench.rs` | Security | 16 |
| 10 | Header Profiler | `header_profiler_bench.rs` | Behavioral | 12 |
| 11 | Sustained | `sustained_bench.rs` | Load testing | 9 |
| 12 | Escalation | `escalation_bench.rs` | Active defense | 11 |
| 13 | Captcha | `captcha_bench.rs` | Challenges | 8 |
| 14 | Hot Path | `hot_path_bench.rs` | Infrastructure | 15 |
| 15–19 | Profiler unit tests | `tests/profiler/*.rs` | Validation | 33 |

## Full Stack Latency Budget

Worst-case per-request latency with all features enabled (~450 μs):

| Subsystem | Cost | % of Total |
| --- | --- | --- |
| Pipeline (ACL → Rate Limit → WAF → Entity) | 73 μs | 16.4% |
| Trends | 97 μs | 21.8% |
| Campaign Correlation | 78 μs | 17.5% |
| DLP Scan (4 KB) | 35 μs | 7.9% |
| Crawler Detection | 3 μs | 0.7% |
| Session Management | 7 μs | 1.6% |
| Profiler | 1 μs | 0.2% |
| Proxy Overhead (Pingora I/O) | ~150 μs | 33.7% |
| **Total (worst case)** | **~450 μs** | **100%** |

::: tip Optimization targets
Trends (21.8%) and Proxy I/O (33.7%) together account for over half of total latency. Proxy overhead is largely TCP/TLS negotiation (irreducible). Trends is an active optimization target — background aggregation could recover ~97 μs.
:::

## Detection Engine

| Operation | Latency |
| --- | --- |
| Simple GET (no params) | ~10 μs |
| SQLi detection (avg) | ~27 μs |
| XSS detection (avg) | ~23 μs |
| Evasive attacks (hex, unicode, polyglot) | ~25–33 μs |
| Full rule set (237 rules) | ~72 μs |

### WAF Rule Scaling

| Active Rules | Analyze Time | Notes |
| --- | --- | --- |
| 10 | 3.7 μs | — |
| 50 | 25.4 μs | — |
| 100 | 34.8 μs | — |
| 237 (full production) | 71.8 μs | Sub-linear scaling via rule indexing |

### Evasion Technique Detection

All evasion techniques detected under 34 μs:

| Technique | Time |
| --- | --- |
| XSS — hex / double / unicode encoding | 26–28 μs |
| SQLi — comment / case / concat evasion | 30–32 μs |
| Path traversal (all variants) | 10–12 μs |
| Command injection | 31–34 μs |
| Polyglot (XSS + SQLi combined) | 26.2 μs |

## Per-Request Hot Path

Sub-microsecond components that run on every request:

| Component | Time | Notes |
| --- | --- | --- |
| Rate limit check (1M RPS capacity) | 60 ns | Token bucket lookup |
| Rate limit (exhausted bucket) | 70 ns | Reject path |
| ACL — 5 rules (first hit) | 6 ns | Early match exit |
| ACL — 100 rules (last match) | 151 ns | Worst case linear scan |
| IPv6 CIDR match | 5.5 ns | Bitwise prefix comparison |
| Tarpit peek | 36–51 ns | Check if IP is tarpitted |

## DLP Scanning

| Payload Size | Clean | With PII | Throughput |
| --- | --- | --- | --- |
| 4 KB | 20.9 μs | 34.4 μs | 187 MiB/s |
| 8 KB | 41.6 μs | 67.2 μs | 188 MiB/s |
| 32 KB | 49.3 μs | — | 635 MiB/s |
| 128 KB | 665 μs | 966 μs | 188 MiB/s |
| 512 KB | 2.6 ms | 3.8 ms | 192 MiB/s |

A 42% faster DLP scanning mode is available for high-throughput scenarios with reduced pattern coverage.

## Intelligence Layer

Per-request overhead for behavioral features:

| Operation | Time |
| --- | --- |
| `apply_rule_risk` (first hit) | 223 ns |
| `apply_rule_risk` (repeat) | 242 ns |
| `check_block` (below threshold) | 155 ns |
| `check_block` (above threshold) | 824 ns |
| Fingerprint register (new) | 1.30 μs |
| Fingerprint lookup (5 IPs) | 327 ns |
| Fingerprint lookup (100 IPs) | 5.24 μs |
| Campaign `record_attack` | 561 ns |
| Campaign `calculate_score` | 3.2 ns |
| `update_profile` (simple GET) | 130 ns |
| `analyze_request` (normal) | 366 ns |
| Session validate (existing) | 300 ns |
| Session create | 6.68 μs |
| Schema learn (small) | 1.85 μs |
| Schema validate (conforming) | 958 ns |
| Bot check (hit) | 747 ns |
| Bot check (miss / full scan) | 3.77 μs |
| Cookie generate (HMAC-SHA256) | 4.06 μs |
| Cookie validate (valid) | 2.73 μs |
| JA4 parse | 1.20 μs |
| Config reload | 236 μs |

## Realistic Payloads

End-to-end latency for production-representative request shapes:

| Scenario | Time | Characteristics |
| --- | --- | --- |
| Simple GET | 10.5 μs | No body, 2–3 headers |
| Clean request w/ 8 headers | 151 μs | Typical browser request |
| E-commerce POST | 2.4 ms | JSON body with cart/payment data |
| GraphQL mutation | 2.8 ms | Complex nested query |
| Healthcare claim | 4.4 ms | Large structured data with PII |
| Heavy — 14 KB + 20 headers | 4.4 ms | Worst-case production request |

**Mixed traffic (95/5 clean/attack):** 20 requests in 277 μs — averaging 13.9 μs per request. Sustained throughput: **72,000 req/s** (single thread).

## Contention Scaling

Concurrent load behavior across shared data structures (10,000 iterations per thread):

| Benchmark | 1 Thread | 4 Threads | 8 Threads | Scaling Factor |
| --- | --- | --- | --- | --- |
| Token bucket | 160 μs | 531 μs | 1.02 ms | 6.4x |
| Entity mgr (90/10 read/write) | 314 μs | 952 μs | 1.45 ms | 4.6x |
| Entity mgr (50/50 read/write) | 351 μs | 1.16 ms | 1.84 ms | 5.2x |
| Tarpit mixed | 215 μs | 777 μs | 1.42 ms | 6.6x |
| DLP scanner | 296 μs | 555 μs | 925 μs | 3.1x |

DLP achieves the best scaling (3.1x degradation at 8 threads) because scanning is embarrassingly parallel — no shared mutable state.

## Comparison

| Implementation | Detection Latency | Throughput | Notes |
| --- | --- | --- | --- |
| **Synapse (Pingora)** | ~75 μs | 13.8K req/s | Pure Rust, no FFI boundary |
| libsynapse (NAPI) | ~73 μs | 14K eval/s | Node.js + Rust FFI overhead |
| Batch 128 (FlatBuffers) | 9.9 μs/req | 101K eval/s | Amortized serialization |
| ModSecurity | 100–500 μs | — | Depends on ruleset |
| AWS WAF | 50–200 μs | — | Cloud service |
| ThreatX SaaS (8-hop) | 1–2+ seconds | — | Sensor → Kafka → MongoDB → HackerMind |

## Known Gaps

- **Contention at 8 threads** — stateful components show 4.6–6.6x degradation under concurrent write load. Acceptable for current targets but limits single-node throughput at very high concurrency.
- **Large payloads** — DLP scan time enters the millisecond range for payloads exceeding 8 KB. Consider body size caps for latency-sensitive endpoints.
- **Sustained load** — all benchmarks are burst-mode (Criterion.rs). No 10+ minute sustained load tests have been performed. Memory growth under extended load is unmeasured.

::: info Test environment
Apple M3 Pro, 36 GB RAM. Rust release build with LTO. 237 production rules, 500+ bot signatures, 22+ DLP patterns. February 2026. All benchmarks are reproducible: `cargo bench` from the synapse-pingora workspace.
:::

## Load Testing

For end-to-end load testing beyond micro-benchmarks:

- `apps/synapse-pingora/docs/performance/TUNNEL_LOAD_TEST.md` — WebSocket tunnel load testing
- `apps/synapse-pingora/docs/performance/BENCHMARK_METHODOLOGY.md` — testing methodology and reproducibility
