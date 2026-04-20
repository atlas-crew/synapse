# Testing Anti-Patterns

## 1. Mocking PrismaClient

**Bad:**
```ts
vi.mock('@prisma/client', () => ({
  PrismaClient: vi.fn(() => ({ sensor: { findMany: vi.fn().mockResolvedValue([...]) }}))
}));
```

**Why it's bad:** You're testing your mock, not your migrations, indexes, constraints, or the actual query shape. Multi-tenant bugs hide behind this.

**Fix:** Use the real dev database with `seedTenant()`. Wrap in a transaction for isolation.

## 2. Cross-Test Data Sharing

**Bad:**
```ts
let sensorId: string;
beforeAll(async () => {
  sensorId = (await createSensor()).id;  // reused across tests
});
```

**Why it's bad:** Test order becomes load-bearing. Parallel runs break. One test's mutation silently passes data to the next.

**Fix:** `beforeEach` seed fresh state. If seeding is expensive, use a transaction that rolls back in `afterEach`.

## 3. Importing the Production Prisma Singleton

**Bad:**
```ts
import { prisma } from '../lib/prisma';  // production singleton
```

**Why it's bad:** Tests share connection pool with dev tooling; DB leaks everywhere.

**Fix:** Inject a `PrismaClient` from the fixture. Production code should already take it as a constructor arg.

## 4. Snapshotting React Components

**Bad:**
```tsx
expect(render(<FleetPanel />).asFragment()).toMatchSnapshot();
```

**Why it's bad:** Snapshots drift, get blindly updated, and don't test behavior. First failing snapshot after a refactor tells you nothing about whether the component works.

**Fix:** Query by role + interact + assert on resulting behavior.
```tsx
render(<FleetPanel sensors={[s]} />);
expect(screen.getByRole('row', { name: /sensor-01/i })).toBeVisible();
await userEvent.click(screen.getByRole('button', { name: /isolate/i }));
expect(onIsolate).toHaveBeenCalledWith(s.id);
```

## 5. Skipping `tenantId` in Fixtures

**Bad:**
```ts
await prisma.sensor.create({ data: { name: 'sensor-01' } });  // no tenantId
```

**Why it's bad:** The test passes locally because Postgres doesn't enforce the multi-tenant invariant at the schema level. Production code breaks under real multi-tenant load.

**Fix:** Always seed via the helper, which enforces `tenantId`.

## 6. Mocking ClickHouse Entirely

**Bad:**
```ts
vi.mock('../storage/clickhouse', () => ({ insert: vi.fn() }));
```

**Why it's bad:** The retry buffer + file retry store are core to the telemetry contract. A test that bypasses them won't catch buffer bugs.

**Fix:** Inject the in-memory transport (see [Fixture Guide](fixtures.md)).

## 7. Asserting on Raw HTTP Status Without Error Body

**Bad:**
```ts
expect(res.status).toBe(400);
```

**Why it's bad:** Any 400 passes — including the wrong 400. Refactors silently break error semantics.

**Fix:**
```ts
expect(res.status).toBe(400);
expect(res.body.error.code).toBe('INVALID_TENANT');
```
