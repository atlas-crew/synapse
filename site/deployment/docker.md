---
title: Docker Deployment
---

# Docker Deployment

## Full Platform (Docker Compose)

Deploy Synapse Fleet with Synapse WAF and local dependencies using Docker
Compose. For a higher-level comparison with Render, Fly.io, Vercel/static
hosting, Railway, Cloud Run, and Kubernetes, see
[Hosting Options](./hosting-options).

Set strong secrets in your shell or `.env` file before starting the stack. Docker
Compose will refuse to start `synapse-fleet` if any required secret is missing.

```yaml
# compose.yml
services:
  synapse-fleet:
    image: nickcrew/synapse-fleet:latest
    ports:
      - "3100:3100"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/synapse_fleet
      CLICKHOUSE_ENABLED: "${CLICKHOUSE_ENABLED:-false}"
      CLICKHOUSE_HOST: clickhouse
      REDIS_URL: redis://redis:6379
      # Replace with the dashboard origin that will call the API.
      CORS_ORIGINS: http://localhost:5180,https://fleet.example.com
      JWT_SECRET: "${JWT_SECRET:?set JWT_SECRET}"
      TELEMETRY_JWT_SECRET: "${TELEMETRY_JWT_SECRET:?set TELEMETRY_JWT_SECRET}"
      CONFIG_ENCRYPTION_KEY: "${CONFIG_ENCRYPTION_KEY:?set CONFIG_ENCRYPTION_KEY}"
      METRICS_AUTH_TOKEN: "${METRICS_AUTH_TOKEN:?set METRICS_AUTH_TOKEN}"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: synapse_fleet
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  synapse-waf:
    image: nickcrew/synapse-waf:latest
    ports:
      - "6190:6190"
    expose:
      - "6191"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    restart: unless-stopped

  clickhouse:
    image: clickhouse/clickhouse-server:23.8
    profiles:
      - analytics
    environment:
      CLICKHOUSE_DB: synapse_fleet
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    restart: unless-stopped

volumes:
  postgres_data:
  clickhouse_data:
```

```sh
docker compose up -d
```

Enable ClickHouse only when you are ready to configure historical analytics:

```sh
CLICKHOUSE_ENABLED=true docker compose --profile analytics up -d
```

## Synapse Standalone (Docker)

```sh
docker run -d \
  --name synapse \
  -p 6190:6190 \
  -p 127.0.0.1:6191:6191 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  nickcrew/synapse-waf:latest
```

The admin and metrics port binds to localhost in this example. Do not expose
port `6191` publicly unless it is protected by a trusted private network.

## Building Images Locally

Both Dockerfiles use multi-stage builds. Build from the repo root:

```sh
# Synapse WAF
docker build -f apps/synapse-pingora/Dockerfile -t nickcrew/synapse-waf:latest .

# Synapse Fleet
docker build -f apps/signal-horizon/Dockerfile -t nickcrew/synapse-fleet:latest .
```

- **Synapse WAF builder stage:** Rust nightly with cmake, openssl, and clang
- **Synapse WAF runtime stage:** `debian:bookworm-slim`, non-root user
- **Exposed ports:** `6190` (proxy), `6191` (admin)

## Scaling Synapse Fleet

The Compose baseline publishes `3100:3100`, which is suitable for one Fleet API
container. To run multiple Fleet API containers, remove the fixed host-port
mapping from `synapse-fleet`, add a load balancer such as Nginx or HAProxy, and
route HTTPS/WSS traffic through that load balancer.

::: warning WebSocket affinity
When running multiple Fleet API instances, use sticky sessions or Redis pub/sub
to ensure WebSocket connections are properly routed. Sensor and dashboard
connections are long-lived.
:::

## Health Checks

Add a health check to the Fleet API service:

```yaml
synapse-fleet:
  healthcheck:
    test:
      [
        "CMD-SHELL",
        "node -e \"require('http').get('http://localhost:3100/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))\"",
      ]
    interval: 10s
    timeout: 5s
    retries: 3
```

The Synapse WAF runtime image is intentionally slim and does not include `curl`.
For WAF health checks, use your orchestrator's TCP/HTTP probe support, bind the
admin port to a private interface for external probing, or build a derived image
that includes a probe client.
