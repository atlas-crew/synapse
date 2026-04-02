---
title: Quick Start
---

# Quick Start

Verify your installation and send your first test traffic. This guide assumes you've already installed Horizon and/or Synapse using one of the methods in the [Installation](./installation) guide.

## 1. Start the Platform

::: code-group

```sh [Docker Compose]
docker compose up -d
```

```sh [npm]
# Start Horizon (requires PostgreSQL)
horizon start

# In another terminal — start Synapse
synapse-waf --config config.yaml
```

```sh [From Source]
just dev
```

:::

After startup, the following services should be available:

| Service | URL |
| --- | --- |
| Horizon API | `http://localhost:3100` |
| Horizon UI | `http://localhost:5180` |
| Synapse (proxy) | `http://localhost:6190` |
| Synapse (admin) | `http://localhost:6191` |

Start services individually with `just dev-horizon` or `just dev-synapse` when running from source.

## 2. Verify

```sh
# Horizon health
curl -s http://localhost:3100/health | jq .

# Synapse health
curl -s http://localhost:6191/status | jq .
```

Open `http://localhost:5180` for the Horizon dashboard.

## 3. Send Test Traffic

```sh
# Clean request — passes through
curl -i http://localhost:6190/

# SQLi test — blocked (HTTP 403)
curl -i "http://localhost:6190/?id=1'%20OR%201=1--"
```

## Troubleshooting

**Port conflicts** — check your `compose.yml` port mappings, `.env` (Horizon), or `config.yaml` (Synapse) for port overrides.

**Database errors** — verify PostgreSQL is running: `pg_isready -h localhost -p 5432`.

**Container not starting** — check logs: `docker compose logs horizon` or `docker compose logs synapse`.

**Rust build failures** (from source only) — ensure nightly toolchain: `rustup default nightly && rustup update`.

## Next Steps

- [Architecture](../architecture/) — how the components fit together
- [Configuration](../configuration/) — configure rules, features, and thresholds
- [Deployment](../deployment/) — production deployment guides
