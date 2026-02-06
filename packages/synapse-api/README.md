# synapse-api

TypeScript client for the Synapse (risk-server) API - WAF sensor management, entity tracking, rule evaluation, and actor fingerprinting.

## Features

- **Full TypeScript Support** - Comprehensive type definitions for all API endpoints
- **Promise-based API** - Modern async/await interface with configurable timeouts
- **Rich Error Handling** - Custom `SynapseError` class with semantic helper methods
- **18 API Methods** - Complete coverage of all Synapse endpoints
- **Debug Mode** - Optional request/response logging for troubleshooting
- **Zero Dependencies** - Uses native `fetch` API

## Installation

```bash
# npm
npm install synapse-api

# pnpm
pnpm add synapse-api

# yarn
yarn add synapse-api
```

## Quick Start

```typescript
import { SynapseClient } from 'synapse-api';

const client = new SynapseClient({
  baseUrl: 'http://localhost:3000'
});

// Check health
const health = await client.health();
console.log(health.status); // "ok"

// Get sensor status
const status = await client.getStatus();
console.log(`Blocked: ${status.blockedRequests}`);

// Evaluate a request (dry-run)
const result = await client.evaluate({
  method: 'GET',
  path: '/api/admin',
  ip: '192.168.1.100'
});
console.log(`Would block: ${result.wouldBlock}`);
```

## Configuration

```typescript
interface SynapseClientOptions {
  /** Base URL of the Synapse server */
  baseUrl: string;

  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;

  /** Enable verbose debug logging (default: false) */
  debug?: boolean;
}
```

## API Reference

### Categories

| Category | Description | Methods |
|----------|-------------|---------|
| **Health & Status** | Server health and metrics | 3 methods |
| **Entity Management** | Tracked entities and blocks | 4 methods |
| **Configuration** | WAF configuration | 2 methods |
| **WAF Rules** | Rule management | 6 methods |
| **Actor Tracking** | Actor fingerprinting | 3 methods |

---

### Health & Status

#### `client.health()`

Check server health status.

```typescript
const health = await client.health();
// { status: 'ok', service: 'synapse', uptime: 3600 }
```

#### `client.getStatus()`

Get sensor status and metrics.

```typescript
const status = await client.getStatus();
// {
//   totalRequests: 10000,
//   blockedRequests: 150,
//   entities: 523,
//   ...
// }
```

#### `client.getMetrics()`

Get Prometheus-formatted metrics.

```typescript
const metrics = await client.getMetrics();
// Raw prometheus text format
```

---

### Entity Management

#### `client.listEntities()`

List all tracked entities.

```typescript
const { entities } = await client.listEntities();
entities.forEach(e => {
  console.log(`${e.ip}: risk ${e.riskScore}`);
});
```

#### `client.listBlocks()`

List all block records.

```typescript
const { blocks } = await client.listBlocks();
blocks.forEach(b => {
  console.log(`${b.ip}: ${b.reason}`);
});
```

#### `client.releaseEntity(entityIdOrIp)`

Release a blocked entity by ID or IP address.

```typescript
await client.releaseEntity('192.168.1.100');
// or
await client.releaseEntity('entity-id-abc123');
```

#### `client.releaseAll()`

Release all blocked entities.

```typescript
const { count } = await client.releaseAll();
console.log(`Released ${count} entities`);
```

---

### Configuration

#### `client.getConfig()`

Get full system configuration.

```typescript
const config = await client.getConfig();
console.log(config.waf.autoblockThreshold);
```

#### `client.updateConfig(updates)`

Update WAF configuration.

```typescript
await client.updateConfig({
  autoblockThreshold: 80,
  riskBasedBlockingEnabled: true
});
```

---

### WAF Rules

#### `client.listRules()`

List all WAF rules (static + runtime).

```typescript
const { rules, stats } = await client.listRules();
console.log(`Total rules: ${stats.total}`);
```

#### `client.addRule(rule, ttl?)`

Add a runtime rule with optional TTL.

```typescript
await client.addRule({
  description: 'Block /admin access',
  blocking: true,
  matches: [{ type: 'path', match: '/admin' }]
}, 3600); // TTL in seconds
```

#### `client.removeRule(ruleId)`

Remove a runtime rule by ID.

```typescript
await client.removeRule(123);
```

#### `client.clearRules()`

Clear all runtime rules.

```typescript
await client.clearRules();
```

#### `client.reloadRules()`

Reload rules from file.

```typescript
await client.reloadRules();
```

#### `client.evaluate(request)`

Evaluate a request against WAF rules (dry-run).

```typescript
const result = await client.evaluate({
  method: 'POST',
  path: '/api/login',
  ip: '192.168.1.100',
  headers: { 'Content-Type': 'application/json' },
  body: '{"username":"admin"}'
});

if (result.wouldBlock) {
  console.log(`Would block: ${result.blockReason}`);
  console.log(`Risk score: ${result.riskScore}`);
}
```

---

### Actor Tracking

#### `client.listActors()`

List all tracked actors.

```typescript
const { actors } = await client.listActors();
actors.forEach(a => {
  console.log(`${a.ip}: fingerprint=${a.fingerprint}`);
});
```

#### `client.getActorStats()`

Get actor tracking statistics.

```typescript
const stats = await client.getActorStats();
console.log(`Total actors: ${stats.totalActors}`);
```

#### `client.setActorFingerprint(ip, fingerprint)`

Set fingerprint for an actor.

```typescript
await client.setActorFingerprint('192.168.1.100', 'fp-abc123');
```

---

## Error Handling

```typescript
import { SynapseClient, SynapseError } from 'synapse-api';

try {
  await client.getStatus();
} catch (error) {
  if (error instanceof SynapseError) {
    console.log(`Status: ${error.statusCode}`);

    if (error.isClientError()) {
      console.log('Client error (4xx)');
    } else if (error.isServerError()) {
      console.log('Server error (5xx)');
    } else if (error.isNetworkError()) {
      console.log('Network/timeout error');
    }
  }
}
```

### SynapseError Methods

| Method | Description |
|--------|-------------|
| `isStatus(code)` | Check for specific HTTP status |
| `isClientError()` | Check if 4xx error |
| `isServerError()` | Check if 5xx error |
| `isNetworkError()` | Check if network/timeout error |

---

## Examples

### Health Monitoring

```typescript
async function monitorHealth(client: SynapseClient) {
  const health = await client.health();
  if (health.status !== 'ok') {
    console.error('Service unhealthy!');
    return false;
  }
  return true;
}

// Poll every 10 seconds
setInterval(() => monitorHealth(client), 10000);
```

### Block Management

```typescript
async function releaseHighRiskEntities(client: SynapseClient, threshold: number) {
  const { entities } = await client.listEntities();
  const highRisk = entities.filter(e => e.riskScore > threshold && e.blocked);

  for (const entity of highRisk) {
    console.log(`Releasing: ${entity.ip} (risk: ${entity.riskScore})`);
    await client.releaseEntity(entity.ip);
  }

  return highRisk.length;
}
```

### Rule Testing

```typescript
async function testRule(client: SynapseClient, rule: RuleDefinition) {
  // Add rule temporarily
  const { rule: added } = await client.addRule(rule, 60); // 1 minute TTL

  // Test against sample requests
  const testRequests = [
    { method: 'GET', path: '/api/users', ip: '10.0.0.1' },
    { method: 'POST', path: '/admin', ip: '10.0.0.1' },
  ];

  for (const req of testRequests) {
    const result = await client.evaluate(req);
    console.log(`${req.method} ${req.path}: ${result.wouldBlock ? 'BLOCKED' : 'ALLOWED'}`);
  }

  // Rule auto-expires after TTL
}
```

---

## TypeScript Types

All types are exported from the main package:

```typescript
import type {
  SynapseClientOptions,
  HealthResponse,
  SensorStatus,
  Entity,
  Block,
  EntitiesResponse,
  BlocksResponse,
  ReleaseResponse,
  ReleaseAllResponse,
  ConfigResponse,
  ConfigUpdateResponse,
  WafConfig,
  Rule,
  RuleDefinition,
  RulesResponse,
  AddRuleResponse,
  RemoveRuleResponse,
  ClearRulesResponse,
  ReloadRulesResponse,
  EvaluateRequest,
  EvaluateResult,
  Actor,
  ActorsResponse,
  ActorStats,
  SetFingerprintResponse,
} from 'synapse-api';
```

---

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Type-check
pnpm type-check

# Run tests
pnpm test

# Watch mode
pnpm test:watch
```

---

## See Also

- **[synapse-client](../../apps/synapse-client)** - CLI wrapper for Synapse API
- **[risk-server](../../apps/risk-server)** - Synapse WAF service
- **[edge-cli](../../apps/edge-cli)** - Unified Edge Labs CLI

---

## License

MIT
