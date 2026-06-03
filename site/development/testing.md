---
title: Testing
---

# Testing

## All Tests

```sh
just test
```

## Horizon

```sh
just test-horizon        # API + UI
just test-horizon-api    # API only
just test-horizon-ui     # UI only (Vitest)
```

## Synapse

### Unit Tests

```sh
just test-synapse        # cargo test
```

### Integration Tests

Integration tests require the `heavy-tests` feature flag and a running Synapse instance:

```sh
just test-synapse-heavy  # cargo test --features heavy-tests
```

### Shell Integration Tests

The shell test script starts a proxy, runs curl-based tests, and verifies detection:

```sh
cd apps/synapse-pingora
./test.sh            # With proxy already running
./test.sh --start    # Start proxy, run tests, stop proxy
```

### Integration Test Suites

| Suite | Tests |
| --- | --- |
| `waf_integration` | Core WAF detection (SQLi, XSS, path traversal) |
| `credential_stuffing` | Login brute-force detection |
| `crawler_detection` | Bot verification and bad bot blocking |
| `dlp_parallel` | Concurrent DLP scanning |
| `filter_chain` | Request filter pipeline ordering |
| `protocol_compat` | HTTP protocol edge cases |
| `tunnel_integration` | WebSocket tunnel to Horizon |
| `horizon_integration` | Signal Horizon hub communication |
| `correlation` | Campaign correlation engine |
| `profiler` | Endpoint schema learning |
| `shadow_mirroring` | Shadow traffic testing |
| `config_validation` | Configuration parsing and validation |
| `reload` | Hot-reload atomicity |
| `honeypot_trap` | Honeypot endpoint detection |
| `chaos` | Stress and fault injection |

## Client Libraries

```sh
just test-synapse-api       # synapse-api package
just test-synapse-client    # synapse-client CLI
```

## Lint and Type-Check

```sh
just lint          # ESLint across all TypeScript projects
just type-check    # TypeScript type checking
just check-synapse # Clippy + rustfmt check
just fmt-synapse   # Auto-format Rust code
```

## Helm Charts

```sh
just helm-deps      # Refresh umbrella chart dependencies without rewriting Chart.lock
just helm-lint       # Lint charts/synapse, charts/synapse-fleet, charts/synapse-waf
just helm-template   # Render the Fleet workload, UI config hooks, and umbrella chart values
just helm-validate   # Lint + render in one local check
```

## CI Pipeline

```sh
just ci         # Full pipeline: lint → type-check → build → test
just ci-ts      # TypeScript projects only
just ci-rust    # Rust projects only
```
