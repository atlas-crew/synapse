# Signal Horizon Hub

Signal Horizon is a multi-tenant fleet management and threat intelligence hub. It ingests threat signals from Synapse sensors, correlates them into campaigns and threats, and distributes intelligence across the fleet.

Think of it as **Netdata Cloud meets CrowdStrike Falcon** for edge security.

## Key Features

- **Fleet Management**: Centralized command and control for distributed Synapse sensors.
- **Threat Intelligence**: Real-time campaign correlation and collective defense.
- **Impossible Travel Detection**: Detect credential compromise through geographic anomalies.
- **Historical Hunting**: Time-window routing between PostgreSQL and ClickHouse for deep forensics.
- **War Room**: Collaborative incident response and automated activity logging.

## Project Structure

```text
signal-horizon/
├── api/             # Node.js/Express Backend
│   ├── src/
│   │   ├── api/     # REST Routes & Middleware
│   │   ├── services/# Core Business Logic (Aggregator, Correlator, Fleet, etc.)
│   │   ├── storage/ # ClickHouse & PostgreSQL (Prisma)
│   │   └── websocket/ # Sensor & Dashboard Gateways
│   └── prisma/      # Postgres Schema & Migrations
├── ui/              # React/Vite/Tailwind Frontend
│   └── src/
│       ├── components/ # Shared UI Elements
│       ├── hooks/      # Custom React Hooks
│       ├── pages/      # View Components (Overview, Hunting, Fleet, etc.)
│       └── stores/     # State Management (Zustand)
├── clickhouse/      # ClickHouse Schema & Init Scripts
├── docs/            # Comprehensive Documentation
└── specs/           # Feature Specifications
```

## Quick Start

### Prerequisites

- Node.js >= 18.18.0
- pnpm 10+
- PostgreSQL (Source of truth)
- Redis (recommended for production queue/distributed state)
- ClickHouse (Optional: Historical analytics)

### Installation

1. Clone the repository
2. From the monorepo root, install dependencies:
   ```bash
   corepack enable
   pnpm install
   ```

3. Setup environment variables:
   - Copy `apps/signal-horizon/api/.env.example` to `apps/signal-horizon/api/.env` and configure.

4. Initialize Database:
   ```bash
   cd apps/signal-horizon/api
   pnpm prisma migrate dev
   # Default seed profile (small):
   pnpm prisma db seed
   # Larger, more "realistic" volumes:
   pnpm run db:seed -- --profile=medium --seed=42 --wipe=true
   ```

### Running the Project

**Start API:**
```bash
pnpm signal-horizon:api
```

**Start UI:**
```bash
pnpm signal-horizon:ui
```

The API will be available at `http://localhost:3100` and the UI at `http://localhost:5180`.

### Single-Process Packaging

Signal Horizon can also run as a single Node-delivered app without Docker. Build the standalone artifact from the monorepo root:

```bash
pnpm signal-horizon:standalone
```

That command builds the Vite UI, builds the API, and copies the UI bundle into `apps/signal-horizon/api/dist/public`. After that, start the API normally:

```bash
cd apps/signal-horizon/api
pnpm start
```

When the bundled UI assets are present, the API serves the dashboard, static assets, and SPA routes itself. PostgreSQL remains required, and Redis/ClickHouse stay optional external dependencies.

### Standalone Release Bundle

To build a customer-handoff artifact for the non-Docker path:

```bash
pnpm signal-horizon:release
```

That creates:

- `apps/signal-horizon/out/signal-horizon-standalone/`
- `apps/signal-horizon/out/signal-horizon-standalone.tar.gz`

The release bundle includes:

- the standalone API+UI runtime
- Prisma migrations and the Prisma CLI for `migrate deploy`
- `.env.example`
- helper scripts in `bin/`
- Nginx, Caddy, and `systemd` examples under `config/`

The release artifact is self-contained for migrations and runtime startup. It does not yet bundle a production-safe first-admin or demo-data bootstrap path.

Use the self-hosted runbook in [`site/guides/self-hosted-standalone.md`](./site/guides/self-hosted-standalone.md) for the exact install flow.

## Deployment

For the managed deployment path, use the repo-root [`render.yaml`](../../render.yaml) plus the Render-specific env templates:

- [`api/.env.render.example`](./api/.env.render.example)
- [`ui/.env.render.example`](./ui/.env.render.example)
- [`scripts/render-preflight.sh`](./scripts/render-preflight.sh)

Run the preflight via:

```bash
bash ./apps/signal-horizon/scripts/render-preflight.sh
```

GitHub Actions also runs the same preflight automatically on Render blueprint changes, root dependency/workspace file changes, plus Signal Horizon API, UI, `shared/`, and deployment-script changes via [`.github/workflows/signal-horizon-preflight.yml`](../../.github/workflows/signal-horizon-preflight.yml).

For customer-managed installs, prefer the standalone bundle plus the self-hosted guide:

- [`site/guides/self-hosted-standalone.md`](./site/guides/self-hosted-standalone.md)
- [`site/deployment.md`](./site/deployment.md)

## Documentation

Comprehensive documentation can be found in the [docs/](./docs/) directory:

- [Architecture Patterns](./docs/architecture.md) - System-wide design decisions and data flows.
- [Rule Authoring Flow](./docs/guides/rule-authoring-flow.md) - How to create and deploy rules (Sigma, UI, Fleet).
- [Fleet Management Spec](./docs/signal-horizon-fleet-management-spec.md) - Detailed fleet operations specification.
- [API Reference](./docs/api.md) - REST and WebSocket protocols.
- [Setup Guide](./docs/setup.md) - Detailed installation and configuration.
- [Fleet Management](./docs/features/fleet-management.md) - Managing sensor fleets.
- [Impossible Travel](./docs/features/impossible-travel.md) - Detection logic and integration.
- [UI Development](./docs/ui-development.md) - Frontend patterns and branding.

## License

Licensed under the GNU Affero General Public License v3.0 only.
Copyright Atlas Crew.
See [LICENSE](../../LICENSE).
