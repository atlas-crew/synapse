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
- PostgreSQL (Source of truth)
- ClickHouse (Optional: Historical analytics)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   # Root
   npm install

   # API
   cd api && npm install

   # UI
   cd ../ui && npm install
   ```

3. Setup environment variables:
   - Copy `api/.env.example` to `api/.env` and configure.

4. Initialize Database:
   ```bash
   cd api
   npx prisma migrate dev
   npx prisma db seed
   ```

### Running the Project

**Start API:**
```bash
cd api
npm run dev
```

**Start UI:**
```bash
cd ui
npm run dev
```

The API will be available at `http://localhost:3000` and the UI at `http://localhost:5173`.

## Documentation

Comprehensive documentation can be found in the [docs/](./docs/) directory:

- [Architecture](./docs/architecture.md) - System design and patterns.
- [API Reference](./docs/api.md) - REST and WebSocket protocols.
- [Setup Guide](./docs/setup.md) - Detailed installation and configuration.
- [Fleet Management](./docs/features/fleet-management.md) - Managing sensor fleets.
- [Impossible Travel](./docs/features/impossible-travel.md) - Detection logic and integration.
- [UI Development](./docs/ui-development.md) - Frontend patterns and branding.

## License

(C) 2025 Atlas Crew. All rights reserved.
