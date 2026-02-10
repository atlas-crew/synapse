# Synapse-Pingora PoC

A proof-of-concept integrating the **real Synapse WAF detection engine** (237 production rules) with Cloudflare's [Pingora](https://github.com/cloudflare/pingora) proxy framework. **Pure Rust, no Node.js, no FFI boundary**.

## Performance Headlines

| Metric | Result |
|--------|--------|
| **Detection Latency** | **~26-50 μs** |
| Rules loaded | **237** production rules |
| Clean traffic | **~2 μs** (no rule matches) |
| Attack traffic | **~18-50 μs** (with entity tracking) |
| vs NAPI (Node.js FFI) | **~2-3x faster** |
| vs ModSecurity | **4-19x faster** |

> **Note**: These numbers use the **real libsynapse engine** with 237 production rules,
> behavioral tracking, entity risk scoring, and the full production rule set.

## Architecture

### Pingora Approach (This PoC)

```
┌─────────────┐     ┌───────────────────────────────┐     ┌──────────────┐
│   Client    │────▶│      Synapse-Pingora          │────▶│   Backend    │
│             │◀────│  ┌─────────────────────────┐  │◀────│   Server     │
└─────────────┘     │  │  libsynapse (in-proc)   │  │     └──────────────┘
                    │  │  • 237 Rules            │  │
                    │  │  • Entity Tracking      │  │
                    │  │  • Risk Scoring         │  │
                    │  └─────────────────────────┘  │
                    │         Single Binary         │
                    └───────────────────────────────┘
```

### Current Approach (nginx + Node.js)

```
┌─────────────┐     ┌─────────┐     ┌──────────────┐     ┌──────────────┐
│   Client    │────▶│  nginx  │────▶│  risk-server │────▶│   Backend    │
│             │◀────│         │◀────│  (Node.js)   │◀────│   Server     │
└─────────────┘     └─────────┘     └──────────────┘     └──────────────┘
                         │                  │
                         │          ┌───────┴────────┐
                         │          │  NAPI Bridge   │
                         │          └───────┬────────┘
                         │          ┌───────┴────────┐
                    config mgmt     │  libsynapse    │
                                    │  (Rust FFI)    │
                                    └────────────────┘
                    └── 3 components, FFI overhead ──┘
```

**Key difference**: Detection happens *inside* the proxy, not across a process boundary.

## Quick Start

```bash
# Build release binary
cargo build --release

# Run (uses default config)
./target/release/synapse-pingora

# Run with interactive TUI dashboard
./target/release/synapse-pingora --tui

# Or with config file
cp config.example.yaml config.yaml
./target/release/synapse-pingora

# Run integration tests
./test.sh
```

## Benchmark Results

Actual results from libsynapse native benchmarks (release build, 100,000 iterations):

| Benchmark | Latency | Throughput | Notes |
|-----------|---------|------------|-------|
| **Clean traffic** | **1.85 μs** | 541,158 req/s | No rules match |
| **SQLi + entity tracking** | **17.74 μs** | 56,381 req/s | 100k unique IPs |
| **SQLi same-IP lookup** | **11.55 μs** | 86,587 req/s | Entity cache hit |
| **Rust-only (no FFI)** | **26.2 μs** | 38,224 req/s | 237 rules, documented |

### Comparison Table

| Implementation | Detection Latency | Throughput | Notes |
|----------------|-------------------|------------|-------|
| **Synapse-Pingora** | **~26 μs** | ~38k req/s | Pure Rust, no FFI boundary |
| libsynapse (NAPI) | ~62-73 μs | ~14k req/s | Node.js + Rust FFI overhead |
| Batch mode (128) | ~9.9 μs | ~101k req/s | FlatBuffers, parallel |
| ModSecurity | 100-500 μs | varies | Depends on ruleset |
| AWS WAF | 50-200 μs | varies | Cloud service |

### Honest Assessment

Pingora eliminates the **~47 μs FFI overhead** (73 μs NAPI vs 26 μs pure Rust), providing
a **~2-3x speedup** over the Node.js architecture. The real value proposition is:

1. **Simpler architecture** - Single Rust binary vs nginx + Node.js + NAPI stack
2. **No serialization boundary** - Detection runs in-process, no IPC
3. **No GC pauses** - No V8 heap, predictable latency
4. **Graceful reload** - Zero-downtime updates via SIGQUIT + socket handoff
5. **Thread-local engines** - Each Pingora worker has its own Synapse instance

### What This Means

| Metric | Current (nginx + NAPI) | Pingora | Improvement |
|--------|------------------------|---------|-------------|
| Per-request latency | ~73 μs | ~26 μs | **2.8x faster** |
| Components to deploy | 3 (nginx, Node.js, NAPI) | 1 binary | **Simpler** |
| Memory footprint | Node.js + V8 heap | Rust only | **~50% smaller** |
| Cold start | Seconds (V8 init) | Milliseconds | **Much faster** |

## Configuration

Copy `config.example.yaml` to `config.yaml`:

```yaml
# Server settings
server:
  listen: "0.0.0.0:6190"
  workers: 0  # 0 = auto-detect

# Upstream backends (round-robin)
upstreams:
  - host: "127.0.0.1"
    port: 8080
  - host: "127.0.0.1"
    port: 8081

# Rate limiting
rate_limit:
  rps: 10000
  enabled: true

# Logging
logging:
  level: "info"  # trace, debug, info, warn, error
  format: "text"
  access_log: true

# Detection toggles
detection:
  sqli: true
  xss: true
  path_traversal: true
  command_injection: true
  action: "block"  # block, log, challenge
  block_status: 403
```

## Pingora Hooks Used

| Hook | Purpose |
|------|---------|
| `early_request_filter` | Rate limiting (pre-TLS) |
| `request_filter` | Attack detection (main filter) |
| `request_body_filter` | Body inspection stub (DLP future) |
| `upstream_peer` | Round-robin backend selection |
| `upstream_request_filter` | Add `X-Synapse-*` headers |
| `logging` | Access logs with timing |

## Integration Tests

Run the test script to verify everything works:

```bash
# With proxy already running
./test.sh

# Or start proxy, run tests, stop proxy
./test.sh --start
```

Sample output:
```
============================================
  Synapse-Pingora Integration Tests
============================================

[INFO] Testing clean requests (should PASS)...
[PASS] Simple GET / (502 - allowed)
[PASS] API endpoint (502 - allowed)
...

[INFO] Testing SQL injection (should BLOCK)...
[PASS] SQLi: OR condition (403) - 2ms
[PASS] SQLi: UNION SELECT (403) - 1ms
...

============================================
  Results: 23/23 passed
============================================

All tests passed!
```

## Graceful Reload

Pingora supports zero-downtime graceful reload:

```bash
# Graceful restart (old workers finish current requests)
pkill -SIGQUIT synapse-pingora && ./target/release/synapse-pingora -u

# The -u flag tells Pingora to take over from the previous instance
```

How it works:
1. `SIGQUIT` tells Pingora to stop accepting new connections
2. Existing requests are allowed to complete
3. New instance starts with `-u` (upgrade) flag
4. Socket is passed from old to new process
5. Old process exits when all requests are done

## Building

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# With full optimizations (LTO + native CPU)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Example Usage

### Clean Request (Allowed)
```bash
curl -v http://localhost:6190/api/users/123
# → Proxied to backend
# → X-Synapse-Analyzed: true
# → X-Synapse-Detection-Time-Us: 1
```

### SQL Injection (Blocked)
```bash
curl -v "http://localhost:6190/api/users?id=1'+OR+'1'%3D'1"
# → HTTP 403 Forbidden
# → {"error": "blocked", "reason": "sqli"}
```

### XSS (Blocked)
```bash
curl -v "http://localhost:6190/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
# → HTTP 403 Forbidden
# → {"error": "blocked", "reason": "xss"}
```

### POST with Body
```bash
curl -v -X POST -d '{"user":"test"}' http://localhost:6190/api/users
# Body size logged: "Request body complete: 15 bytes"
```

## Upstream Headers

The proxy adds these headers to upstream requests:

| Header | Description |
|--------|-------------|
| `X-Synapse-Analyzed` | Always "true" |
| `X-Synapse-Detection-Time-Us` | Detection time in microseconds |
| `X-Synapse-Client-IP` | Client IP (from X-Forwarded-For or connection) |

## Detection Engine

This PoC uses the **real libsynapse engine** from `../risk-server/libsynapse/`, which includes:

- **237 production rules** covering SQLi, XSS, path traversal, command injection, and more
- **Behavioral tracking** - Entity risk accumulates across requests from the same IP
- **Risk scoring** - Graduated risk levels (0-100) with configurable blocking thresholds
- **Rule chaining** - Multiple rules can match and contribute to overall risk

### Verified Detections

Tested and verified to block:
- `UNION SELECT` SQLi attacks (rule 200200)
- Path traversal attempts (rules 200014, 200016)
- Various other attack patterns from the production rule set

### Rules Loading

Rules are loaded at startup from (in order of preference):
1. `../risk-server/libsynapse/rules.json` (production rules)
2. `rules.json` (local override)
3. `/etc/synapse-pingora/rules.json` (system-wide)
4. `src/minimal_rules.json` (fallback with 7 basic patterns)

## Performance Optimizations

1. **Thread-local engines**: Each Pingora worker has its own Synapse instance
2. **Lazy rule loading**: Rules parsed once at startup via `once_cell::Lazy`
3. **Zero-copy headers**: Header references passed directly to engine
4. **LTO**: Link-time optimization in release builds (profile: fat LTO, 1 codegen unit)
5. **Native CPU**: Build with `RUSTFLAGS="-C target-cpu=native"` for best performance

### DLP Body Inspection Optimizations

The DLP scanner has been optimized for high-throughput request body scanning:

| Optimization | Description | Impact |
|--------------|-------------|--------|
| **Content-Type Short Circuit** | Skip binary types (image/*, video/*, multipart/form-data) | Eliminates scan overhead for file uploads |
| **Inspection Depth Cap** | Truncate body to first 8KB by default | O(1) scan time for large payloads |
| **Aho-Corasick Prefilter** | Single-pass multi-pattern detection | 30-50% faster than sequential regex |

#### DLP Performance Benchmarks

| Payload Size | With PII | Clean Traffic | Notes |
|--------------|----------|---------------|-------|
| 4 KB | **~45 μs** | ~33 μs | E-commerce order payloads |
| 8 KB | ~86 μs | ~73 μs | At inspection cap limit |
| 18 KB | ~100 μs | ~76 μs | Truncated to 8KB cap |
| 32 KB | ~85 μs | ~65 μs | Plateaus due to truncation |

#### DLP Configuration Options

```rust
// In code (DlpConfig)
DlpConfig {
    enabled: true,                        // Enable/disable DLP scanning
    max_scan_size: 5 * 1024 * 1024,       // 5MB hard limit (reject if larger)
    max_matches: 100,                     // Stop after 100 matches
    scan_text_only: true,                 // Only scan text content types
    max_body_inspection_bytes: 8 * 1024,  // 8KB inspection cap (truncate, don't reject)
}
```

**Tuning Recommendations**:
- **High-security environments**: Set `max_body_inspection_bytes` to 32KB+ for deeper inspection
- **High-throughput APIs**: Keep default 8KB cap for sub-100μs scan times
- **File upload endpoints**: Binary content types are automatically skipped

#### Content Types Automatically Skipped

- `image/*` - All image formats
- `audio/*` - All audio formats
- `video/*` - All video formats
- `application/octet-stream` - Binary data
- `multipart/form-data` - File uploads
- `application/zip`, `application/gzip`, etc. - Archives
- `font/*` - Font files
- `model/*` - 3D models

## Future Work (For Feature Parity with nginx)

### Core Features (Required for Production)
- [x] Full detection rule parity with libsynapse (DONE - using real engine)
- [x] **Multi-site/vhost support** - Hostname-based routing with per-site config
- [x] **TLS termination** - SSL certificates, SNI support
- [x] **Health check endpoint** - `/_sensor/status` equivalent
- [x] **Per-site WAF config** - Override rules, thresholds per hostname

### Management Features (Important)
- [x] **Metrics endpoint** - Prometheus-compatible `/metrics`
- [x] **Config hot-reload API** - Update config without restart
- [x] **Access lists** - Allow/deny CIDRs per site
- [x] **Per-site rate limiting** - Hostname-aware rate limits
- [x] Signal Horizon telemetry integration

### Advanced Features
- [x] DLP scanning in `request_body_filter` (DONE - with performance optimizations)
- [x] Request body inspection (POST/PUT payloads) (DONE - with truncation cap)
- [x] Custom block pages per site
- [x] Dashboard UI integration (Dashboard compatibility routes)
- [x] Production hardening (security audit remediations complete)

## Files

```
synapse-pingora/
├── Cargo.toml           # Dependencies (includes libsynapse)
├── config.example.yaml  # Example configuration
├── test.sh              # Integration test script
├── README.md            # This file
├── src/
│   ├── main.rs          # Full implementation with real engine
│   └── minimal_rules.json  # Fallback rules (7 patterns)
└── benches/
    └── detection.rs     # Criterion benchmarks
```

## License

Copyright AtlasCrew, LLC

## See Also

- [Pingora GitHub](https://github.com/cloudflare/pingora)
- [Pingora Documentation](https://docs.rs/pingora)
- [libsynapse](../risk-server/libsynapse/) - Full Synapse engine
