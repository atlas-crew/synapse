---
title: Docker Deployment
---

# Docker Deployment

## Full Platform (Docker Compose)

Deploy Horizon with all dependencies using Docker Compose:

```yaml
# compose.yml
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
      clickhouse:
        condition: service_started
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
    restart: unless-stopped

  clickhouse:
    image: clickhouse/clickhouse-server:23.8
    environment:
      CLICKHOUSE_DB: signal_horizon
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  synapse:
    image: nickcrew/synapse-waf:latest
    ports:
      - "6190:6190"
      - "6191:6191"
    volumes:
      - ./config.yaml:/etc/synapse/config.yaml:ro
    restart: unless-stopped

volumes:
  postgres_data:
  clickhouse_data:
```

```sh
docker compose up -d
```

## Synapse Standalone (Docker)

```sh
docker run -d \
  --name synapse \
  -p 6190:6190 \
  -p 6191:6191 \
  -v $(pwd)/config.yaml:/etc/synapse/config.yaml:ro \
  nickcrew/synapse-waf:latest
```

## Building Images Locally

Both Dockerfiles use multi-stage builds. Build from the repo root:

```sh
# Synapse WAF
docker build -f apps/synapse-pingora/Dockerfile -t synapse-waf:latest .

# Horizon
docker build -f apps/signal-horizon/Dockerfile -t horizon:latest .
```

- **Builder stage:** `rust:1.77-bookworm` with cmake, openssl, clang
- **Runtime stage:** `debian:bookworm-slim`, non-root user, ~50 MB image
- **Exposed ports:** `6190` (proxy), `6191` (admin)

## Scaling Horizon

```sh
docker compose up -d --scale horizon=3
```

::: warning WebSocket affinity
When running multiple Horizon instances, use sticky sessions or Redis pub/sub to ensure WebSocket connections are properly routed. Sensor and dashboard connections are long-lived.
:::

## Health Checks

Add health checks to your compose file:

```yaml
horizon:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:3100/health"]
    interval: 10s
    timeout: 5s
    retries: 3

synapse:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:6191/status"]
    interval: 10s
    timeout: 5s
    retries: 3
```
