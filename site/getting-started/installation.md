---
title: Installation
---

# Installation

There are several ways to install Horizon and Synapse. Docker is the recommended method for most users. npm packages are available as an alternative. Building from source is intended for contributors and advanced users.

## Docker (Recommended) {#docker}

Docker is the fastest way to get running — no build tools or language runtimes required.

### Full Platform

Deploy Horizon with Synapse and all dependencies using Docker Compose:

```yaml
# compose.yml
services:
  horizon:
    image: nickcrew/horizon:latest
    ports:
      - "3100:3100"
      - "5180:5180"
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/signal_horizon
      CLICKHOUSE_ENABLED: "true"
      CLICKHOUSE_HOST: clickhouse
      REDIS_URL: redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  synapse:
    image: nickcrew/synapse-waf:latest
    ports:
      - "6190:6190"
      - "6191:6191"
    volumes:
      - ./config.yaml:/etc/synapse/config.yaml:ro
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

volumes:
  postgres_data:
  clickhouse_data:
```

```sh
docker compose up -d
```

### Synapse Standalone

Run Synapse as a standalone WAF without the Horizon hub:

```sh
docker run -d \
  --name synapse \
  -p 6190:6190 \
  -p 6191:6191 \
  -v $(pwd)/config.yaml:/etc/synapse/config.yaml:ro \
  nickcrew/synapse-waf:latest
```

See [Synapse Configuration](../configuration/synapse) for a full config reference, or use the [example config](https://github.com/atlas-crew/edge-protection/blob/main/apps/synapse-waf/config.example.yaml) as a starting point.

::: tip Available tags
Both images publish `latest` and semver tags (e.g., `nickcrew/synapse-waf:0.6.0`). Pin to a specific version in production.
:::

## npm {#npm}

All packages are published under the `@atlascrew` scope on npm.

### Horizon

```sh
npm install -g @atlascrew/horizon

# Start the server
horizon start
```

Horizon requires PostgreSQL 15+ and optionally ClickHouse and Redis. See the [Horizon Configuration](../configuration/horizon) reference for environment variables.

### Synapse WAF

```sh
npm install -g @atlascrew/synapse-waf

# Start with a config file
synapse-waf --config config.yaml
```

### Client Libraries

Use the client libraries to integrate with Synapse and Horizon programmatically:

```sh
# Synapse API client library
npm install @atlascrew/synapse-api

# Synapse CLI
npm install -g @atlascrew/synapse-client
```

## From Source (Advanced) {#from-source}

Building from source is intended for contributors and advanced users who need to modify the platform. This requires the full development toolchain (Node.js, pnpm, Rust nightly, and system dependencies).

```sh
git clone https://github.com/atlas-crew/edge-protection.git
cd edge-protection
pnpm install
```

See [Local Environment Setup](../development/local-setup) for the complete development workflow, including database setup and running dev servers.

::: info Rust build time
The first Synapse build fetches and compiles all Rust dependencies, which can take several minutes. Subsequent builds are incremental and much faster.
:::

## Next Steps

- [Quick Start](./quickstart) — verify your installation and send test traffic
- [Configuration](../configuration/) — configure rules, features, and thresholds
- [Deployment](../deployment/) — production deployment guides
