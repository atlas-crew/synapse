---
name: edge-protection-data
description: Manage the Edge Protection data architecture, including PostgreSQL (Prisma) and ClickHouse schemas. Use when modifying database models, running migrations, or seeding data for the Signal Horizon hub.
---

# Edge Protection Data Strategy

This skill provides the procedural knowledge required to manage the project's polyglot data layer (Postgres for relational state, ClickHouse for telemetry).

## Database Split

- **PostgreSQL (Prisma)**: Stores multi-tenant configuration, user data, sensor metadata, and relational state.
  - Path: `apps/signal-horizon/api/prisma/schema.prisma`.
- **ClickHouse**: Stores high-volume time-series telemetry, signals, and audit logs.
  - Path: `apps/signal-horizon/clickhouse/schema.sql`.

## Essential Commands

Always run these from the project root using `just`:
- **Prisma**:
  - `just db-generate`: Regenerate the Prisma client.
  - `just db-migrate`: Run Prisma migrations (dev).
  - `just db-seed`: Seed with the default profile.
  - `just db-reseed`: Wipe and seed from scratch.
- **ClickHouse**:
  - `just ch-start / ch-stop`: Control the local ClickHouse server.
  - `just ch-init`: Initialize the `signal_horizon` ClickHouse schema.
- **Monitoring**:
  - `just services`: Check if Postgres (5432) and ClickHouse (8123) are UP.

## Bundled Utilities

- **`scripts/wipe_db.cjs`**: A safe, procedural script that deletes all data from the Postgres database in dependency order.
  - Usage: `node scripts/wipe_db.cjs [--dry-run]`

## Schema Conventions

- **Multi-Tenancy**: Every relational model in Postgres must link to a `Tenant` via `tenantId`.
- **CUIDs**: Use `cuid()` for primary keys in Postgres.
- **Telemetry Links**: ClickHouse signals are correlated to Postgres entities via `sensorId`, `tenantId`, or `request_id`.
- **Enums**: Always use uppercase Enums for consistency.

See [Data Conventions](references/conventions.md) for detailed rules.

## Workflow

1. **Research**: Identify if the change affects relational state (Postgres) or telemetry (ClickHouse).
2. **Implementation**: 
   - For Postgres: Update `schema.prisma`.
   - For ClickHouse: Update `schema.sql`.
3. **Migration**: Run `just db-migrate` or `just ch-init`.
4. **Validation**: Run `just db-generate` to update types, then run `just type-check`.
5. **Testing**: Use `node scripts/wipe_db.cjs` followed by `just db-seed` to verify with fresh data.

## Resources

- [Schema Reference](references/schemas.md): High-level overview of core models and ClickHouse tables.
- [Data Conventions](references/conventions.md): Strict rules for models, relationships, and naming.
