# Synapse Fleet API Architecture

## Service Pipeline

```
Sensor WS  →  SensorGateway  →  Aggregator  →  Correlator  →  Broadcaster  →  DashboardGateway
                                      ↓             ↓
                                  ClickHouse    Postgres
                                  (telemetry)   (campaigns)
```

- **Aggregator** (`services/aggregator/`): Normalizes raw sensor signals into canonical event shapes. Writes to ClickHouse via `ClickHouseService` + retry buffer.
- **Correlator** (`services/correlator/`): Clusters events into campaigns using entity graphs and temporal proximity. Persists campaigns to Postgres.
- **Broadcaster** (`services/broadcaster/`): Fans out new campaigns + alerts to dashboards via `DashboardGateway`.

## WebSocket Gateways

| Gateway             | Direction     | Auth                | Purpose                          |
|---------------------|---------------|---------------------|----------------------------------|
| `SensorGateway`     | Sensor → Hub  | Sensor key          | Ingest telemetry from WAF sensors|
| `DashboardGateway`  | Hub → UI      | Dashboard API key   | Push events/alerts to UI         |
| `LogStreamer`       | Hub → UI      | Dashboard API key   | Live tail sensor logs            |
| `TunnelBroker`      | Both          | Tunnel session      | Encrypted tunnel sessions        |

Upgrade routing is done in `websocket/upgrade-path.ts`.

## Background Jobs (BullMQ)

| Queue              | Purpose                                    |
|--------------------|--------------------------------------------|
| `retention-queue`  | TTL-driven deletion of old Postgres rows   |
| `sigma-hunt-queue` | Retroactive Sigma rule hunts over history  |
| `blocklist-queue`  | Distribute blocklist updates to sensors    |
| `rollout-worker`   | Staged rule rollouts to the fleet          |

All queues are registered in `jobs/index.ts` and share connection + telemetry via `jobs/queue.ts`.

## Storage Layer

- **Postgres (Prisma)**: Relational state. Multi-tenant via `tenantId` on every row.
- **ClickHouse**: Time-series telemetry. Writes go through `ClickHouseService` with `ClickHouseRetryBuffer` (in-memory) and `FileRetryStore` (durable) so restarts don't lose signals.
- **Redis**: Session state + BullMQ queues.

## Services of Note

- `FleetAggregator`, `FleetCommander`: fleet-wide state + command distribution.
- `RuleDistributor`: pushes rule updates to sensors (coordinates with `rollout-worker`).
- `WarRoomService` + `PlaybookService`: incident response orchestration.
- `ImpossibleTravelService`: geo-temporal anomaly detection.
- `APIIntelligenceService`: API schema learning and drift detection.
