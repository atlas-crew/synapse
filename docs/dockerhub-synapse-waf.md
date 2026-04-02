# Synapse WAF

High-performance Web Application Firewall and reverse proxy built on Cloudflare Pingora. Single Rust binary with 237 detection rules, 25 DLP patterns, and sub-10 microsecond clean request latency at 72K req/s sustained throughput.

Part of the [Edge Protection](https://github.com/inferno-lab/edge-protection) platform alongside [Signal Horizon](https://hub.docker.com/r/nickcrew/horizon).

## Quick Start

```bash
docker run -p 6190:6190 -p 6191:6191 nickcrew/synapse-waf
```

- Proxy listener: `localhost:6190`
- Admin API & metrics: `localhost:6191`
- Health check: [localhost:6191/status](http://localhost:6191/status)
- Prometheus metrics: [localhost:6191/metrics](http://localhost:6191/metrics)

## Exposed Ports

| Port | Purpose |
|------|---------|
| `6190` | Proxy listener (client traffic) |
| `6191` | Admin API, metrics, console |

## Configuration

Mount a `config.yaml` to customize behavior:

```bash
docker run -p 6190:6190 -p 6191:6191 \
  -v ./config.yaml:/app/config.yaml:ro \
  nickcrew/synapse-waf
```

### Minimal config.yaml

```yaml
server:
  listen: "0.0.0.0:6190"
  admin_listen: "0.0.0.0:6191"
  workers: 0  # auto-detect CPU count

upstreams:
  - host: "host.docker.internal"
    port: 8080

detection:
  sqli: true
  xss: true
  path_traversal: true
  command_injection: true
  action: "block"
  block_status: 403

rate_limit:
  enabled: true
  rps: 10000

logging:
  level: "info"
  format: "json"
  access_log: true
```

### Key configuration sections

| Section | Purpose |
|---------|---------|
| `server` | Listener addresses, worker count |
| `upstreams` | Backend servers to proxy to |
| `detection` | WAF rules — SQLi, XSS, path traversal, command injection |
| `dlp` | Data loss prevention — credit cards, SSN, API keys, JWT, medical records |
| `rate_limit` | Per-IP token bucket rate limiting |
| `access_lists` | CIDR-based allow/deny (IPv4/IPv6) |
| `tarpit` | Progressive response delays for attackers |
| `traps` | Honeypot endpoints |
| `tls` | Per-domain TLS termination |
| `telemetry` | Signal Horizon integration |

### Hot reload

Apply config changes without downtime (~240 microsecond atomic swap, zero dropped requests):

```bash
curl -X POST http://localhost:6191/reload -H "X-Admin-Key: $ADMIN_KEY"
```

### Validate config

```bash
docker run --rm -v ./config.yaml:/app/config.yaml:ro \
  nickcrew/synapse-waf check-config /app/config.yaml
```

## Detection Capabilities

- **WAF**: 237 production rules — SQLi, XSS, path traversal, command injection
- **DLP**: 25 sensitive data patterns — credit cards, SSN, IBAN, API keys, JWT, RSA/EC keys, medical records
- **Bot detection**: 46 malicious signatures, 19 crawler definitions
- **Credential stuffing**: behavioral detection
- **API profiling**: anomaly detection with learned baselines
- **Entity & actor tracking**: risk scoring and behavioral fingerprinting
- **Session hijacking**: detection via anomaly signals
- **Campaign correlation**: cross-request attack grouping
- **GeoIP & impossible travel**: geographic anomaly detection

## Using with Signal Horizon

[Signal Horizon](https://hub.docker.com/r/nickcrew/horizon) is the fleet intelligence hub that aggregates signals from distributed Synapse sensors. Connect Synapse to Horizon for centralized threat correlation and fleet management.

```yaml
# In config.yaml
telemetry:
  enabled: true
  endpoint: "http://horizon:3100/telemetry"
  api_key: "your-api-key"
  batch_size: 100
  flush_interval: 10s
```

## Using with Chimera (WAF Testing)

[Chimera](https://hub.docker.com/r/nickcrew/chimera) provides 456+ intentionally vulnerable endpoints — the ideal backend target for testing Synapse's detection rules.

```bash
# Start Chimera as the vulnerable backend
docker run -d --name chimera -p 8880:8880 -e DEMO_MODE=full nickcrew/chimera

# Start Synapse proxying to Chimera
docker run -d --name synapse -p 6190:6190 -p 6191:6191 \
  -v ./config.yaml:/app/config.yaml:ro \
  nickcrew/synapse-waf
```

With `config.yaml` pointing upstream at Chimera:

```yaml
upstreams:
  - host: "host.docker.internal"
    port: 8880
```

## Full Platform (Compose)

Run Synapse WAF with Signal Horizon for fleet intelligence, backed by PostgreSQL and optional ClickHouse for historical analytics:

```yaml
services:
  synapse:
    image: nickcrew/synapse-waf:latest
    ports:
      - "6190:6190"
      - "6191:6191"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    networks:
      - edge
    restart: unless-stopped

  horizon:
    image: nickcrew/horizon:latest
    ports:
      - "3100:3100"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/signal_horizon
      CLICKHOUSE_ENABLED: "true"
      CLICKHOUSE_HOST: clickhouse
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - edge
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: signal_horizon
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - edge

  clickhouse:
    image: clickhouse/clickhouse-server:23.8
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    networks:
      - edge

networks:
  edge:

volumes:
  postgres_data:
  clickhouse_data:
```

```bash
docker compose up -d
```

| Service | URL |
|---------|-----|
| Synapse Proxy | [localhost:6190](http://localhost:6190) |
| Synapse Admin | [localhost:6191](http://localhost:6191) |
| Horizon API | [localhost:3100](http://localhost:3100) |

## Performance

| Benchmark | Latency |
|-----------|---------|
| Clean GET detection | ~10 microseconds |
| Full pipeline | ~72 microseconds |
| WAF + DLP (4 KB body) | ~247 microseconds |
| Sustained throughput | 72K req/s |
| DLP throughput | 188 MiB/s |
| Hot reload | ~240 microseconds |

## Links

- [Documentation](https://edge.atlascrew.dev)
- [GitHub](https://github.com/inferno-lab/edge-protection)
- [CLI](https://www.npmjs.com/package/@atlascrew/synapse-client)
