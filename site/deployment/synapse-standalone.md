---
title: Deploy Synapse Standalone
---

# Deploy Synapse Standalone

Run Synapse as a standalone WAF without the Horizon hub. This is the simplest deployment — a single binary in front of your upstream servers.

## When to Use Standalone

- You need a fast WAF with minimal operational overhead
- You don't need centralized fleet management or cross-tenant correlation
- You want to evaluate Synapse before deploying the full platform

## Install

### Docker (Recommended)

```sh
docker run -d \
  --name synapse \
  -p 6190:6190 \
  -p 6191:6191 \
  -v $(pwd)/config.yaml:/etc/synapse/config.yaml:ro \
  nickcrew/synapse-waf:latest
```

### npm

```sh
npm install -g @atlascrew/synapse-waf
synapse-waf --config config.yaml
```

### Build from Source

For contributors and advanced users with the Rust nightly toolchain:

```sh
cd apps/synapse-pingora

# Release build (recommended)
cargo build --release

# With native CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The binary is at `target/release/synapse-waf`.

## Configuration

Copy the example config and customize:

```sh
cp config.example.yaml config.yaml
```

Minimal standalone configuration:

```yaml
server:
  listen: "0.0.0.0:6190"
  workers: 0  # auto-detect CPU count

upstreams:
  - host: "127.0.0.1"
    port: 8080

rate_limit:
  rps: 10000
  enabled: true

detection:
  sqli: true
  xss: true
  path_traversal: true
  command_injection: true
  action: "block"
  block_status: 403

logging:
  level: "info"
  format: "json"
  access_log: true
```

## Running

```sh
# Standard mode
./target/release/synapse-waf

# With interactive TUI dashboard
./target/release/synapse-waf --tui

# With explicit config path
./target/release/synapse-waf --config /etc/synapse/config.yaml
```

## TLS Termination

Enable TLS with optional per-domain SNI certificates:

```yaml
tls:
  enabled: true
  cert_path: "/etc/synapse/certs/default.pem"
  key_path: "/etc/synapse/keys/default.key"
  min_version: "1.2"
  per_domain_certs:
    - domain: "api.example.com"
      cert_path: "/etc/synapse/certs/api.pem"
      key_path: "/etc/synapse/keys/api.key"
```

## DLP Scanning

Enable Data Loss Prevention to detect PII in request bodies:

```yaml
dlp:
  enabled: true
  max_body_inspection_bytes: 8192  # 8 KB inspection cap
  scan_text_only: true
  action: "mask"  # mask, hash, block, or log
  patterns:
    - name: "credit_card"
      pattern: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      action: "mask"
    - name: "ssn"
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      action: "block"
```

::: tip DLP performance
Binary content types (images, video, archives) are automatically skipped. The 8 KB inspection cap keeps scan times under 100 μs for most payloads.
:::

## Health Check

Synapse exposes a health endpoint at `/_sensor/status` on the proxy port and the admin API on port `6191`:

```sh
# Proxy health
curl http://localhost:6190/_sensor/status

# Admin status
curl http://localhost:6191/status
```

## Configuration Hot-Reload

Update configuration without restarting or dropping connections:

```sh
curl -X POST http://localhost:6191/reload \
  -H "X-Admin-Key: $ADMIN_KEY"
```

The reload takes ~240 μs via atomic `RwLock` swap. In-flight requests are unaffected.

## Upstream Headers

Synapse adds these headers to forwarded requests:

| Header | Value |
| --- | --- |
| `X-Synapse-Analyzed` | `true` |
| `X-Synapse-Detection-Time-Us` | Detection latency in microseconds |
| `X-Synapse-Client-IP` | Resolved client IP |

## Graceful Shutdown

Synapse handles `SIGTERM`, `SIGQUIT`, and `SIGINT`:

1. Stop accepting new connections
2. Drain in-flight requests
3. Exit when all connections close (up to `shutdown_timeout_secs`)
