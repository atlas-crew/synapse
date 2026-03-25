# Signal Horizon Deployment Guide

This guide covers deploying Signal Horizon, the central command plane for Atlas Crew sensor fleets.

The repo now includes a baseline Render Blueprint at [`render.yaml`](../../../render.yaml) for the current monorepo layout. Use it as the source of truth for a managed deployment of the UI, API, PostgreSQL, and Redis.

Render-specific environment templates are available at [`api/.env.render.example`](../api/.env.render.example), [`ui/.env.render.example`](../ui/.env.render.example), and a local preflight script is available at [`scripts/render-preflight.sh`](../scripts/render-preflight.sh).

## Architecture Overview

Signal Horizon consists of three main components:

| Component | Purpose | Port |
|-----------|---------|------|
| API Server | REST API and WebSocket gateway | 3100 by default, or platform-provided `PORT` |
| PostgreSQL | Real-time data, configuration state | 5432 |
| Redis | Job queue and distributed state | 6379 |
| ClickHouse | Historical data, time-series analytics | 8123/9000 |

```mermaid
graph TD
    LB[Load Balancer<br/>HTTPS Termination]
    API[Signal Horizon API<br/>Express + WS Gateway]
    
    subgraph Storage ["Database Cluster"]
        PG[(PostgreSQL<br/>Real-time State)]
        CH[(ClickHouse<br/>Historical Analytics)]
        RD[(Redis<br/>Session Cache)]
    end

    LB --> API
    API --> PG
    API --> CH
    API --> RD
```

## Dependency Tiers

| Dependency | Required | Why it exists |
|-----------|----------|---------------|
| PostgreSQL | Yes | Prisma source of truth for tenants, sensors, auth, fleet state, rollouts, and core API data |
| Redis | Recommended for production | BullMQ queues, rollout processing, and distributed caches/state fall back to in-memory without it |
| ClickHouse | Optional | Historical hunting, telemetry retention, and larger time-series analytics |

### Minimum Viable Deployment

- UI static host
- API web service
- PostgreSQL

This is enough to boot the product, but background job behavior and distributed state will degrade if Redis is absent, and historical hunt/analytics features will be limited without ClickHouse.

### Recommended Production Deployment

- UI static host
- API web service
- PostgreSQL
- Redis
- ClickHouse only if you want historical hunting and archive-scale analytics on day one

## Prerequisites

- Node.js 20+
- PostgreSQL 15+
- Redis 7+ for production-grade queue/state behavior
- ClickHouse 23.8+ only if historical queries are required
- A host or platform that supports long-lived Node processes and WebSocket upgrades

## Environment Configuration

Create a `.env` file with the following variables:

```bash
# Server Configuration
NODE_ENV=production
HOST=0.0.0.0
PORT=3100

# PostgreSQL (Required)
DATABASE_URL=postgresql://user:password@localhost:5432/signal_horizon

# Redis (Recommended for production - queues and distributed state)
REDIS_URL=redis://localhost:6379
ENABLE_JOB_QUEUE=true

# Security
JWT_SECRET=your-jwt-secret-min-32-chars
TELEMETRY_JWT_SECRET=your-telemetry-jwt-secret-min-32-chars
CONFIG_ENCRYPTION_KEY=your-config-encryption-key
CORS_ORIGINS=https://app.signal-horizon.example.com

# ClickHouse (Optional - enables historical queries)
CLICKHOUSE_ENABLED=false
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_HTTP_PORT=8123
CLICKHOUSE_DB=signal_horizon
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=your-secure-password
```

## Database Setup

### PostgreSQL Schema

Run the Prisma migrations to set up the PostgreSQL schema:

```bash
cd apps/signal-horizon/api
pnpm prisma migrate deploy
```

The schema includes:
- `Sensor` - Registered sensors and their status
- `ConfigTemplate` - Configuration templates
- `ConfigSyncState` - Per-sensor config sync tracking
- `Command` - Command queue for sensors
- `SavedQuery` - Saved hunt queries

### ClickHouse Schema

If using ClickHouse for historical data, apply the schema:

```bash
clickhouse-client --host localhost --query "$(cat apps/signal-horizon/clickhouse/schema.sql)"
```

Key tables:
- `signal_events` - Time-series signal data
- `campaign_timeline` - Campaign state history
- `signal_hourly_mv` - Hourly aggregations (materialized view)

## Deployment Options

### Option 1: Render Blueprint (Recommended Managed Path)

Use the repo-root [`render.yaml`](../../../render.yaml) to create:

- `signal-horizon-ui` static site
- `signal-horizon-api` Node web service
- `signal-horizon-postgres` managed Postgres
- `signal-horizon-redis` managed Key Value / Redis

The baseline blueprint intentionally leaves the following values for dashboard entry during initial creation:

- `VITE_API_URL`
- `VITE_WS_URL`
- `VITE_HORIZON_API_KEY`
- `CORS_ORIGINS`

Recommended custom-domain shape:

- UI: `https://app.signal-horizon.example.com`
- API: `https://api.signal-horizon.example.com`
- Dashboard WebSocket: `wss://api.signal-horizon.example.com/ws/dashboard`

ClickHouse is not defined inside the Blueprint. If you need historical hunting on day one, create ClickHouse separately and set the `CLICKHOUSE_*` variables on the API service.

Before the first platform deploy, run:

```bash
bash ./apps/signal-horizon/scripts/render-preflight.sh
```

The repo also runs this same check automatically in CI via the repo-root workflow file `.github/workflows/signal-horizon-preflight.yml` whenever the Render blueprint, root dependency/workspace files, or Signal Horizon API, UI, `shared/`, and deployment-script paths change.

### Option 2: Native Installation / VM

For bare-metal or VM deployment:

```bash
# Install dependencies
cd apps/signal-horizon/api
pnpm install --prod

# Run migrations
pnpm prisma migrate deploy

# Start server
NODE_ENV=production node dist/index.js
```

Use a process manager like PM2:

```bash
pm2 start dist/index.js --name signal-horizon -i max
```

Pair this with:

- a static host or reverse proxy serving `apps/signal-horizon/ui/dist`
- PostgreSQL
- Redis for queue-backed rollouts and distributed state
- optional ClickHouse for historical analytics

### Option 3: Docker / Kubernetes

These are viable deployment shapes, but the repo does not currently ship production-ready `Dockerfile`, Compose, or `k8s/` assets for Signal Horizon.

Treat them as custom packaging work, not turnkey checked-in deployment targets.

## Load Balancer Configuration

### Synapse WAF Example

The Rust binary is `synapse-waf`, but the checked-in package directory and example config path still use `synapse-pingora`.

```yaml
# /etc/synapse-pingora/config.yaml
server:
  listen: "0.0.0.0:443"

upstreams:
  - host: "127.0.0.1"
    port: 3100

logging:
  level: "info"
  access_log: true

tls:
  enabled: true
  cert_path: "/etc/ssl/certs/signal-horizon.crt"
  key_path: "/etc/ssl/private/signal-horizon.key"
```

Ensure your edge proxy supports WebSocket upgrades for `/ws`.

### AWS ALB

For AWS Application Load Balancer:

1. Create target group with health check path `/health`
2. Enable sticky sessions for WebSocket connections
3. Configure idle timeout to 300 seconds (for long-lived WS connections)
4. Use ACM certificate for HTTPS

## Sensor Registration

### Generate Sensor Credentials

```bash
# Create onboarding token via API
curl -X POST https://signal-horizon.example.com/api/v1/onboarding/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "US East Registration Token",
    "expiresInHours": 24,
    "metadata": {
      "region": "us-east-1"
    }
  }'
```

Response includes the sensor ID and authentication token:

```json
{
  "id": "token-abc123",
  "token": "sensor-token-xyz789",
  "wsEndpoint": "wss://signal-horizon.example.com/ws/sensors"
}
```

The onboarding token is not the final sensor ID. The sensor presents that token during registration or approval, and Signal Horizon then assigns a permanent sensor identifier such as `sensor-abc123`.

### Sensor Configuration

Configure the Atlas Crew sensor to connect to Signal Horizon:

```yaml
# sensor.yaml
signal_horizon:
  enabled: true
  endpoint: wss://signal-horizon.example.com/ws/sensors
  sensor_id: sensor-abc123
  token: sensor-token-xyz789
  heartbeat_interval: 60s
  reconnect_delay: 5s
  max_reconnect_delay: 60s
```

## High Availability

### PostgreSQL HA

Use PostgreSQL replication for high availability:

```yaml
# Primary
postgresql:
  primary:
    enabled: true
  replica:
    enabled: true
    replicas: 2
```

### ClickHouse Cluster

For large-scale deployments, use ClickHouse cluster:

```xml
<clickhouse>
  <remote_servers>
    <signal_horizon_cluster>
      <shard>
        <replica>
          <host>clickhouse-1</host>
          <port>9000</port>
        </replica>
        <replica>
          <host>clickhouse-2</host>
          <port>9000</port>
        </replica>
      </shard>
    </signal_horizon_cluster>
  </remote_servers>
</clickhouse>
```

### API Server Scaling

Scale API servers horizontally:

```bash
# Docker Compose
docker compose up -d --scale signal-horizon=3

# Kubernetes
kubectl scale deployment signal-horizon --replicas=3
```

Considerations:
- Use Redis for shared session state
- WebSocket connections are per-server (use sticky sessions or Redis pub/sub)
- Command queue uses PostgreSQL for consistency

## Monitoring

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Basic service health check used for platform health probes; the API does not currently expose separate readiness or liveness endpoints |
| `GET /metrics` | Prometheus metrics endpoint |

### Prometheus Metrics

Protect the metrics endpoint with a bearer token for non-local access:

```bash
METRICS_AUTH_TOKEN=your-metrics-bearer-token
```

Key metrics:
- `signal_horizon_sensors_total` - Total connected sensors
- `signal_horizon_commands_queued` - Pending commands
- `signal_horizon_ws_connections` - Active WebSocket connections
- `signal_horizon_query_duration_seconds` - Query latencies

### Grafana Dashboards

Import the provided dashboards:

```bash
# Fleet Overview
grafana-cli dashboards install signal-horizon-fleet

# Query Performance
grafana-cli dashboards install signal-horizon-queries
```

## Backup and Recovery

### PostgreSQL Backup

```bash
# Daily backup
pg_dump -h localhost -U postgres signal_horizon | gzip > backup-$(date +%Y%m%d).sql.gz

# Restore latest automated backup (backup-YYYYMMDD.sql.gz)
LATEST_BACKUP=$(ls -t backup-*.sql.gz | head -n 1)
gunzip -c "$LATEST_BACKUP" | psql -h localhost -U postgres signal_horizon
```

### ClickHouse Backup

```bash
# Backup tables
clickhouse-backup create signal_horizon_$(date +%Y%m%d)

# Restore latest automated backup (signal_horizon_YYYYMMDD)
LATEST_CH_BACKUP=$(clickhouse-backup list | awk 'NR>1 {print $1}' | tail -n 1)
clickhouse-backup restore "$LATEST_CH_BACKUP"
```

## Security Hardening

### Network Security

1. **Firewall rules**: Only allow necessary ports
   - 443: HTTPS/WSS (public)
   - 5432: PostgreSQL (internal only)
   - 8123/9000: ClickHouse (internal only)
   - 6379: Redis (internal only)

2. **TLS configuration**: Use TLS 1.3, disable older versions

3. **API authentication**: Require JWT or API key for all endpoints

### Secrets Management

Use a secrets manager (Vault, AWS Secrets Manager, etc.):

```bash
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id signal-horizon/prod | jq -r '.SecretString' > .env
```

### Audit Logging

Enable audit logging for compliance:

```bash
AUDIT_LOG_ENABLED=true
AUDIT_LOG_DESTINATION=cloudwatch  # or file, syslog
```

## Troubleshooting

### Sensor Connection Issues

```bash
# Check WebSocket connections
curl -s localhost:3003/api/fleet/metrics | jq '.totalSensors'

# View sensor logs
docker compose logs signal-horizon | grep "sensor connection"
```

### Database Connection Pool

If seeing connection errors:

```bash
# Check active connections
psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'signal_horizon'"

# Increase pool size
DATABASE_POOL_SIZE=50
```

### ClickHouse Query Performance

```sql
-- Check slow queries
SELECT query, query_duration_ms
FROM system.query_log
WHERE type = 'QueryFinish'
  AND query_duration_ms > 1000
ORDER BY query_duration_ms DESC
LIMIT 10;
```

## Upgrade Procedure

### Rolling Upgrade

1. Build new image:
   ```bash
   docker build -t atlascrew/signal-horizon:2.5.0 .
   ```

2. Run migrations:
   ```bash
   docker run --rm atlascrew/signal-horizon:2.5.0 pnpm prisma migrate deploy
   ```

3. Rolling restart:
   ```bash
   kubectl rollout restart deployment signal-horizon
   ```

4. Verify health:
   ```bash
   kubectl rollout status deployment signal-horizon
   ```

### Rollback

```bash
# Kubernetes
kubectl rollout undo deployment signal-horizon

# Docker Compose
docker compose pull  # pulls previous image
docker compose up -d
```

## Related Documentation

- [Fleet API](./fleet-api.md) - Fleet management API reference
- [Hunt API](./hunt-api.md) - Threat hunting queries
- [ClickHouse Schema](../clickhouse/schema.sql) - Historical data schema
