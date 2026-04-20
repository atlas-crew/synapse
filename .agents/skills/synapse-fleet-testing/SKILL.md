---
name: synapse-fleet-testing
description: Apply the testing strategy for Synapse Fleet TypeScript projects (API, UI, shared packages). Use when writing Vitest tests, setting up fixtures, or diagnosing flaky or DB-backed tests across apps/signal-horizon and packages/.
---

# Synapse Fleet Testing Strategy

This skill governs Vitest-based testing for the Synapse Fleet TypeScript surface. Rust/Cargo tests are owned by `synapse-waf-dev`.

## Where Tests Live

- **API**: `apps/signal-horizon/api/src/**/*.test.ts` — co-located with source.
- **UI**: `apps/signal-horizon/ui/src/**/*.test.{ts,tsx}` — co-located with components.
- **Shared**: `apps/signal-horizon/shared/src/**/*.test.ts`.
- **Packages**: `packages/synapse-api/**/*.test.ts`, `packages/signal-ui/**/*.test.ts`.

## Core Rules

- **Real Prisma, not mocks.** API tests run against the actual dev Postgres (seeded). Mocking Prisma hides migration drift and multi-tenant bugs. Use `prisma.$transaction(fn, { rollback: true })` or a per-test schema if isolation is needed.
- **Mock external services.** Apparatus SSE, Horizon hub, and outbound HTTP must be mocked. Use `vi.fn()` or the fixture helpers under `api/src/__tests__/`.
- **Mock ClickHouse carefully.** Prefer `ClickHouseService` with a test transport over ad-hoc mocks. The retry buffer is part of the contract.
- **UI: React Testing Library only.** No enzyme. Query by role/label, not by test-id unless there's no a11y-native option.
- **Tenant scope in every test.** API tests must seed a tenant and pass `tenantId` through fixtures. Tests that skip this pass locally but hide production bugs.

## Common Anti-Patterns (flag & fix)

- Mocking `PrismaClient` wholesale.
- Using `beforeAll` to seed data, then relying on order across tests.
- Importing `prisma` from the production singleton — tests should use the injected client.
- Asserting on render output rather than behavior (e.g. snapshotting instead of interacting).

## Bundled Utilities

- **`scripts/find_prisma_mocks.cjs`**: Scans `**/*.test.ts` under `apps/signal-horizon/api/` for tests that mock `PrismaClient` or `@prisma/client`. Flags each match so they can be reviewed against the "real Prisma" rule.
  - Usage: `node scripts/find_prisma_mocks.cjs`

## Workflow

1. **Write the test first** for the behavior you're about to implement.
2. **Run just that test**: `pnpm --filter <pkg> test -- <pattern>` or `pnpm exec nx run signal-horizon-api:test -- <pattern>`.
3. **Watch it fail** for the right reason. A test that passes before the code is written is testing nothing.
4. **Implement**, re-run, confirm green.
5. **Full suite** before commit: `pnpm exec nx run signal-horizon-api:test` (or `:ui:test`).

## Resources

- [Fixture Guide](references/fixtures.md): Tenant-seeded fixtures, ClickHouse test transport, SSE mock.
- [Anti-Patterns Catalog](references/anti-patterns.md): Full list of Prisma-mock / cross-test-dependency pitfalls with fix recipes.
