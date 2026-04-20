# Fixture Guide

## Tenant-Seeded Fixtures

Most API tests need a tenant, an API key, and at least one sensor. The canonical helper lives in `apps/signal-horizon/api/src/__tests__/fixtures.ts`.

```ts
import { seedTenant } from '../__tests__/fixtures';

describe('GET /v1/fleet/sensors', () => {
  it('lists sensors for the tenant', async () => {
    const { tenant, apiKey, sensor } = await seedTenant();
    const res = await request(app)
      .get('/v1/fleet/sensors')
      .set('X-API-Key', apiKey);
    expect(res.status).toBe(200);
    expect(res.body.sensors[0].id).toBe(sensor.id);
  });
});
```

Rules:
- Always use `seedTenant()` (or the equivalent per-domain helper). Don't hand-roll tenants in tests.
- Wrap in a transaction or clean up in `afterEach`. Don't leak rows across tests.
- Never share `tenantId` across test files. Each file gets its own.

## ClickHouse Test Transport

`ClickHouseService` accepts an injectable transport. In tests, use `InMemoryClickHouseTransport` (under `storage/__tests__/`):

```ts
const transport = new InMemoryClickHouseTransport();
const ch = new ClickHouseService({ transport });
// ... exercise the service
expect(transport.inserted('signals')).toHaveLength(3);
```

Do not mock `ClickHouseService` directly — the retry buffer is part of the contract you want to test.

## Apparatus SSE Mock

Apparatus outbound calls should be mocked at the transport layer:

```ts
import { mockApparatus } from '../__tests__/mocks/apparatus';

const apparatus = mockApparatus({ signals: [{...}] });
```

The mock simulates SSE event framing so the bridge adapter exercises the same code path as prod.

## WebSocket Gateway Fixtures

For `SensorGateway` / `DashboardGateway` tests, use the `testServer` helper (real `ws` server on a random port):

```ts
const { url, close } = await startTestSensorGateway();
const client = new WebSocket(url, { headers: { 'X-Sensor-Key': key }});
// ... drive the client
await close();
```

Avoid mocking `WebSocket` itself — real socket behavior is the contract.

## BullMQ Test Mode

Queues should use the in-process worker for tests (`queue.ts` supports a `testMode`):

```ts
const queue = createRetentionQueue({ testMode: true });
await queue.add(...);
await queue.drain();  // runs jobs synchronously
```
