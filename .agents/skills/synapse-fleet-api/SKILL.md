---
name: synapse-fleet-api
description: Build and modify the Synapse Fleet API backend (Express + Prisma + WebSockets + BullMQ). Use when adding HTTP routes under apps/signal-horizon/api/src/api/routes, editing services, wiring WebSocket gateways, or changing background jobs. Directory is retained as signal-horizon per the phased Synapse Fleet rename.
---

# Synapse Fleet API Strategy

This skill covers the backend of the Synapse Fleet hub: HTTP routing, the service pipeline, WebSocket gateways, and BullMQ jobs. The directory `apps/signal-horizon/api/` is intentionally unchanged per the phased rename (see `apps/signal-horizon/docs/architecture/adr-0003-synapse-fleet-rename.md`).

## Surface Map

- **`api/routes/`**: Express routers grouped by domain (`fleet*.ts`, `hunt*.ts`, `auth*.ts`, `campaigns.ts`, `blocklist.ts`, etc.). Each router is mounted in `app-shell.ts`.
- **`middleware/`**: `security.ts`, `rate-limiter.ts`, `content-type.ts`, `csrf.ts`, `request-id.ts`, `timeout.ts`, `versioning.ts`, `replay-protection.ts`. Do not reinvent — compose existing middleware.
- **`services/`**: Domain services. Pipeline is `aggregator/ → correlator/ → broadcaster/`. Also: `fleet/`, `hunt/`, `intel/`, `warroom/`, `sigma-hunt/`, `api-intelligence/`, `impossible-travel.ts`.
- **`websocket/`**: `sensor-gateway.ts` (inbound sensor telemetry), `dashboard-gateway.ts` (fan-out to UI), `log-streamer.ts`, `tunnel-broker.ts`.
- **`jobs/`**: BullMQ. `retention-queue.ts`, `sigma-hunt-queue.ts`, `blocklist-queue.ts`, `rollout-worker.ts`. All share `queue.ts`.
- **`storage/`**: Prisma (Postgres) + `ClickHouseService` + `ClickHouseRetryBuffer` + `FileRetryStore` for durable telemetry writes.

## Mandatory Patterns

- **Multi-tenant filtering**: Every Prisma query that touches tenant data must filter by `tenantId`. If a route doesn't have a `tenantId` in scope, it is almost certainly wrong.
- **Service injection**: Wire services in `index.ts`, not inline in route handlers. Routes take services via factory closures.
- **Telemetry writes**: Never call `ClickHouseService.insert` directly from a route. Use the aggregator or the retry-buffered path so failures survive restarts.
- **WebSocket auth**: Sensor connections authenticate with a sensor key; dashboard connections use API keys. `upgrade-path.ts` routes them.
- **Job scheduling**: Register new queues in `jobs/index.ts`. Don't spawn ad-hoc workers.

## Bundled Utilities

- **`scripts/check_service_wiring.cjs`**: Scans `api/routes/*.ts` for handlers that call Prisma directly without `tenantId` filtering — a common multi-tenant bug.
  - Usage: `node scripts/check_service_wiring.cjs`

## Workflow

1. **Route**: Add or edit a file under `api/routes/`. Mount in `app-shell.ts`.
2. **Service**: Put business logic in `services/`. Inject via `index.ts`.
3. **Storage**: Prefer repo/service methods; raw Prisma in routes is a smell.
4. **Test**: Use Vitest. Co-locate tests as `*.test.ts`. Mock external services, not Prisma — the test DB is real.
5. **Validate**: `pnpm exec nx run signal-horizon-api:test` and `:lint`.

## Resources

- [Architecture Map](references/architecture.md): Service pipeline, WebSocket gateways, job queues.
- [Route Conventions](references/routes.md): Naming, versioning, middleware stack, error contract.
