# Setup Guide

This guide covers setting up the Signal Horizon Hub for local development.

## Prerequisites

- **Node.js**: v18.18.0 or higher.
- **PostgreSQL**: v14 or higher (Source of truth).
- **ClickHouse**: (Optional) v23.x or higher (Historical analytics).
- **Package Manager**: `npm` or `pnpm` (examples use `npm`).

## Environment Configuration

Both the API and UI require environment variables to function correctly.

### API Configuration

1. Copy the example file:
   ```bash
   cp api/.env.example api/.env
   ```

2. Configure core variables:
   - `DATABASE_URL`: Your PostgreSQL connection string.
   - `CLICKHOUSE_ENABLED`: Set to `true` if you have a ClickHouse instance running.
   - `CORS_ORIGINS`: Ensure your UI URL is included (default: `http://localhost:5173`).

### UI Configuration

The UI uses Vite's environment variables. Ensure the API base URL matches your local API.

## Database Setup

### 1. PostgreSQL (Prisma)

Signal Horizon uses Prisma as its ORM for PostgreSQL.

```bash
cd api
# Install dependencies
npm install

# Run migrations to create the schema
npx prisma migrate dev --name init

# Seed the database with demo data (tenants, API keys, sensors)
npx prisma db seed
```

### 2. ClickHouse (Optional)

If `CLICKHOUSE_ENABLED=true`, you must initialize the ClickHouse schema.

```bash
# Using the provided init script (requires clickhouse-client or curl)
./clickhouse/init.sh
```

Or manually run the schema in `clickhouse/schema.sql`.

## Installation & Running

### Full Install

```bash
npm install
cd api && npm install
cd ../ui && npm install
```

### Running in Development

**Start the Backend:**
```bash
cd api
npm run dev
```

**Start the Frontend:**
```bash
cd ui
npm run dev
```

## Troubleshooting

### Database Connectivity
If the API fails to start, verify your `DATABASE_URL`. Ensure the database exists and the user has sufficient permissions.

### ClickHouse Errors
If you see `ClickHouse connection failed` in the logs, the system will fallback to "PostgreSQL-only" mode. This is normal if you haven't set up ClickHouse.

### WebSocket Connections
If the dashboard fails to connect, check your `CORS_ORIGINS` in the API's `.env` and verify the `WS_DASHBOARD_PATH`.
