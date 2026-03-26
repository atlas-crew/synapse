# Self-Hosted Standalone Bundle

Signal Horizon can ship as one Node-delivered bundle that serves both the UI and API from the same process. This is the primary non-Docker install path for customer-managed environments.

## What You Get

- One Node runtime that serves the dashboard, REST API, and WebSocket endpoints from the same origin
- Required PostgreSQL support
- Optional Redis and ClickHouse wiring through environment variables
- Local migration and startup helpers inside the release artifact
- Reverse-proxy examples for Nginx and Caddy

## Build The Release Artifact

From the monorepo root:

```bash
pnpm signal-horizon:release
```

That command creates:

- `apps/signal-horizon/out/signal-horizon-standalone/`
- `apps/signal-horizon/out/signal-horizon-standalone.tar.gz`

The release intentionally includes the Prisma CLI so the artifact can run `migrate deploy` on its own. That makes it larger than a runtime-only bundle, but it avoids a separate source checkout just to initialize PostgreSQL.

## Host Prerequisites

- Node.js 22 LTS recommended
- PostgreSQL 15+
- Redis 7+ if you want queue-backed rollouts and distributed state
- ClickHouse 23.8+ only if you need historical hunting and archive-scale analytics
- A reverse proxy that supports WebSocket upgrades

## Install On A Host

1. Copy `signal-horizon-standalone.tar.gz` to the target host.
2. Extract it into a final install path such as `/opt/signal-horizon`.
3. Copy `.env.example` to `.env` and set the required values.
4. Run migrations.
5. Start the service directly or under `systemd`.

Example:

```bash
mkdir -p /opt
tar -xzf signal-horizon-standalone.tar.gz -C /opt
mv /opt/signal-horizon-standalone /opt/signal-horizon
cd /opt/signal-horizon
cp .env.example .env
$EDITOR .env
./bin/migrate.sh
./bin/start.sh
```

## Required And Optional Environment

Required:

- `NODE_ENV=production`
- `DATABASE_URL=postgresql://...`
- `JWT_SECRET=...`
- `TELEMETRY_JWT_SECRET=...`

Recommended:

- `REDIS_URL=redis://...`
- `ENABLE_JOB_QUEUE=true`

Optional:

- `CLICKHOUSE_ENABLED=true`
- `CLICKHOUSE_HOST=...`
- `CLICKHOUSE_HTTP_PORT=8123`
- `CLICKHOUSE_DB=signal_horizon`
- `CLICKHOUSE_USER=...`
- `CLICKHOUSE_PASSWORD=...`

Same-origin defaults:

- Keep the app behind one hostname such as `https://signal-horizon.example.com`
- Leave the Node process on an internal port such as `127.0.0.1:3100`
- Terminate TLS at Nginx or Caddy

## First Login / Evaluation Data

The standalone artifact can run migrations by itself. It does not yet include a dedicated production-safe first-admin or demo-data bootstrap flow.

If you need seeded demo data, use the source-tree seed workflow against the target PostgreSQL database from a checkout of the same revision:

```bash
cd apps/signal-horizon/api
pnpm run db:seed -- --profile=small --seed=42 --wipe=false
```

That path is suitable for evaluation only, not for customer production data.

## Running Under systemd

The bundle ships with `config/systemd/signal-horizon.service`.

Typical install:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin signal-horizon
sudo chown -R signal-horizon:signal-horizon /opt/signal-horizon
sudo cp config/systemd/signal-horizon.service /etc/systemd/system/signal-horizon.service
sudo systemctl daemon-reload
sudo systemctl enable --now signal-horizon
sudo systemctl status signal-horizon
```

Update `WorkingDirectory`, `EnvironmentFile`, `User`, and `Group` in the unit file to match your host.

## Reverse Proxy

The bundle includes:

- `config/nginx/signal-horizon.conf`
- `config/caddy/Caddyfile`

Both examples forward `/`, `/api/v1`, and `/ws` to the same Node process so BrowserRouter routes and WebSocket upgrades work without cross-origin configuration.

## Operational Notes

- PostgreSQL is required. The app will not start without `DATABASE_URL`.
- Redis is optional for boot, but production behavior degrades without it because queue-backed jobs and distributed state fall back to in-memory behavior.
- ClickHouse is optional and should stay disabled unless you need historical hunt and telemetry retention features.
- The release artifact is generated from the current monorepo workspace, so rebuild it after any API or UI change.
