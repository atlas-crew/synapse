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
