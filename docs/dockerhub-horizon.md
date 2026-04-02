# Signal Horizon

Multi-tenant fleet intelligence hub and management control plane for distributed Synapse WAF sensors. Centralized threat correlation, impossible travel detection, historical hunting, and collaborative incident response.

Part of the [Edge Protection](https://github.com/inferno-lab/edge-protection) platform alongside [Synapse WAF](https://hub.docker.com/r/nickcrew/synapse-waf).

## Quick Start

Horizon requires PostgreSQL as its source of truth:

```bash
# Start PostgreSQL
docker run -d --name postgres \
  -e POSTGRES_DB=signal_horizon \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:15-alpine

# Start Horizon
docker run -p 3100:3100 \
  -e DATABASE_URL=postgresql://postgres:postgres@host.docker.internal:5432/signal_horizon \
  nickcrew/horizon
```

- API: [localhost:3100](http://localhost:3100)
- WebSocket (sensors): `ws://localhost:3100/ws/sensors`
- WebSocket (dashboard): `ws://localhost:3100/ws/dashboard`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | API server port |
| `HOST` | `0.0.0.0` | Bind address |
| `NODE_ENV` | `development` | Environment (`production` recommended) |
| `DATABASE_URL` | — | PostgreSQL connection string (**required**) |
| `LOG_LEVEL` | `info` | Logging level |

### WebSocket

| Variable | Default | Description |
|----------|---------|-------------|
| `WS_SENSOR_PATH` | `/ws/sensors` | Sensor connection endpoint |
| `WS_DASHBOARD_PATH` | `/ws/dashboard` | Dashboard connection endpoint |
| `WS_HEARTBEAT_INTERVAL_MS` | `30000` | Heartbeat interval |
| `WS_MAX_SENSOR_CONNECTIONS` | `1000` | Max sensor connections |
| `WS_MAX_DASHBOARD_CONNECTIONS` | `100` | Max dashboard connections |

### Signal Processing

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNAL_BATCH_SIZE` | `100` | Signals per batch |
| `SIGNAL_BATCH_TIMEOUT_MS` | `5000` | Max batch wait time |
| `BLOCKLIST_PUSH_DELAY_MS` | `50` | Blocklist propagation delay |
| `BLOCKLIST_CACHE_SIZE` | `100000` | Max cached blocklist entries |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY_HEADER` | `X-API-Key` | Header for API authentication |
| `CONFIG_ENCRYPTION_KEY` | — | Encryption key for stored configs |
| `TELEMETRY_JWT_SECRET` | — | JWT secret for telemetry auth |
| `CORS_ORIGINS` | — | Comma-separated allowed origins |

### Optional Services

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | — | Redis connection string (recommended for production) |
| `CLICKHOUSE_ENABLED` | `false` | Enable ClickHouse for historical analytics |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse host |
| `CLICKHOUSE_HTTP_PORT` | `8123` | ClickHouse HTTP port |
| `CLICKHOUSE_DB` | `signal_horizon` | ClickHouse database |
| `CLICKHOUSE_USER` | `default` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | — | ClickHouse password |

## Key Features

- **Fleet Management** — centralized command and control for distributed Synapse sensors
- **Threat Intelligence** — real-time campaign correlation across tenants
- **Impossible Travel Detection** — geographic anomaly detection for credential compromise
- **Historical Hunting** — time-window routing between PostgreSQL and ClickHouse
- **War Room** — collaborative incident response workspace

## Dependencies

| Service | Required | Purpose |
|---------|----------|---------|
| PostgreSQL 15+ | **Yes** | Source of truth for tenants, configs, signals |
| Redis 7+ | Recommended | Queue, distributed state, pub/sub |
| ClickHouse 23+ | Optional | Historical analytics and long-term signal storage |

## Using with Synapse WAF

[Synapse WAF](https://hub.docker.com/r/nickcrew/synapse-waf) sensors connect to Horizon via WebSocket to stream detection signals and receive blocklist updates. Configure Synapse's telemetry section to point at Horizon:

```yaml
# In Synapse config.yaml
telemetry:
  enabled: true
  endpoint: "http://horizon:3100/telemetry"
  api_key: "your-api-key"
  batch_size: 100
  flush_interval: 10s
```

## Full Platform (Compose)

Run Horizon with Synapse WAF, PostgreSQL, and optional ClickHouse:

```yaml
services:
  horizon:
    image: nickcrew/horizon:latest
    ports:
      - "3100:3100"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/signal_horizon
      CLICKHOUSE_ENABLED: "true"
      CLICKHOUSE_HOST: clickhouse
      REDIS_URL: redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - edge
    restart: unless-stopped

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

  redis:
    image: redis:7-alpine
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
| Horizon API | [localhost:3100](http://localhost:3100) |
| Synapse Proxy | [localhost:6190](http://localhost:6190) |
| Synapse Admin | [localhost:6191](http://localhost:6191) |

## Also available on npm

```bash
npm install -g @atlascrew/horizon
horizon start
```

## Links

- [Documentation](https://edge.atlascrew.dev)
- [GitHub](https://github.com/inferno-lab/edge-protection)
- [npm](https://www.npmjs.com/package/@atlascrew/horizon)
