---
title: Synapse Fleet Configuration
---

# Synapse Fleet Configuration

Synapse Fleet API (formerly Signal Horizon) is configured via environment variables, typically set in a `.env` file at `apps/signal-horizon/api/.env`. The `apps/signal-horizon/` directory path and `HORIZON_*` env var names are intentionally unchanged in this phase — see [ADR-0003](https://github.com/atlas-crew/edge-protection/blob/main/apps/signal-horizon/docs/architecture/adr-0003-synapse-fleet-rename.md).

## Server

| Variable | Default | Description |
| --- | --- | --- |
| `NODE_ENV` | `development` | `production` enables optimizations and stricter defaults |
| `PORT` | `3100` | HTTP listener port |
| `HOST` | `0.0.0.0` | Bind address |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error` |

## Database (PostgreSQL)

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `DATABASE_URL` | — | **Yes** | PostgreSQL connection string (e.g., `postgresql://user:pass@host:5432/signal_horizon`) |

## ClickHouse (Optional)

| Variable | Default | Description |
| --- | --- | --- |
| `CLICKHOUSE_ENABLED` | `false` | Enable ClickHouse for historical queries |
| `CLICKHOUSE_HOST` | `localhost` | Hostname |
| `CLICKHOUSE_HTTP_PORT` | `8123` | HTTP API port |
| `CLICKHOUSE_DB` | `signal_horizon` | Database name |
| `CLICKHOUSE_USER` | `default` | Username |
| `CLICKHOUSE_PASSWORD` | — | Password |
| `CLICKHOUSE_COMPRESSION` | `true` | Enable compression |
| `CLICKHOUSE_MAX_CONNECTIONS` | `10` | Connection pool size |

::: info When to enable ClickHouse
Enable ClickHouse when you need time-series queries over large signal volumes or retention beyond what PostgreSQL comfortably handles. For small deployments (< 10 sensors), PostgreSQL alone is sufficient.
:::

## WebSocket

| Variable | Default | Description |
| --- | --- | --- |
| `WS_SENSOR_PATH` | `/ws/sensors` | Sensor ingestion endpoint |
| `WS_DASHBOARD_PATH` | `/ws/dashboard` | Dashboard push endpoint |
| `WS_HEARTBEAT_INTERVAL_MS` | `30000` | Heartbeat interval (ms) |
| `WS_MAX_SENSOR_CONNECTIONS` | `1000` | Max concurrent sensor connections |
| `WS_MAX_DASHBOARD_CONNECTIONS` | `100` | Max concurrent dashboard connections |

## Signal Processing

| Variable | Default | Description |
| --- | --- | --- |
| `SIGNAL_BATCH_SIZE` | `100` | Signals per aggregation batch |
| `SIGNAL_BATCH_TIMEOUT_MS` | `5000` | Max wait before flushing a batch |
| `BLOCKLIST_PUSH_DELAY_MS` | `50` | Delay before broadcasting blocklist updates |
| `BLOCKLIST_CACHE_SIZE` | `100000` | In-memory blocklist capacity |

## Security

| Variable | Default | Description |
| --- | --- | --- |
| `API_KEY_HEADER` | `X-API-Key` | Header name for API key authentication |
| `CORS_ORIGINS` | — | Comma-separated allowed origins |
| `CONFIG_ENCRYPTION_KEY` | — | Encryption key for sensitive config fields at rest |
| `TELEMETRY_JWT_SECRET` | — | JWT secret for sensor telemetry endpoint (`/_sensor/report`) |

::: warning Production secrets
In production, set `CONFIG_ENCRYPTION_KEY` and `TELEMETRY_JWT_SECRET` to strong random values (32+ characters). Use a secrets manager (Vault, AWS Secrets Manager) rather than storing them in `.env` files.
:::

## Example Configurations

### Development

```sh
NODE_ENV=development
PORT=3100
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/signal_horizon?schema=public
LOG_LEVEL=debug
CLICKHOUSE_ENABLED=false
CORS_ORIGINS=http://localhost:5180,http://127.0.0.1:5180
```

### Production

```sh
NODE_ENV=production
PORT=3100
DATABASE_URL=postgresql://app:$DB_PASSWORD@db.internal:5432/signal_horizon
LOG_LEVEL=info
CLICKHOUSE_ENABLED=true
CLICKHOUSE_HOST=clickhouse.internal
CLICKHOUSE_PASSWORD=$CH_PASSWORD
CORS_ORIGINS=https://horizon.example.com
CONFIG_ENCRYPTION_KEY=$ENCRYPTION_KEY
TELEMETRY_JWT_SECRET=$JWT_SECRET
WS_MAX_SENSOR_CONNECTIONS=5000
```
