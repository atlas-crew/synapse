# Synapse Client

TypeScript client and CLI for the Synapse (risk-server) API.

## Installation

```bash
# From the monorepo root
pnpm install
pnpm nx run synapse-client:build

# Run CLI
node apps/synapse-client/dist/cli.js --help

# Or link globally
cd apps/synapse-client && npm link
synapse --help
```

## CLI Usage

```bash
# Set server URL via environment variable
export SYNAPSE_URL=http://localhost:3000

# Check health
synapse health

# Get sensor status
synapse status

# List entities
synapse entities

# Release a blocked entity
synapse release 192.168.1.100

# List WAF rules
synapse rules

# Evaluate a request against rules
synapse evaluate GET "/api/users?id=1"

# Get JSON output
synapse --json status
```

### Global Options

| Flag | Env Var | Description |
|------|---------|-------------|
| `-u, --url` | `SYNAPSE_URL` | Synapse server URL (required) |
| `--json` | `SYNAPSE_JSON=1` | Output as JSON |
| `-d, --debug` | `SYNAPSE_DEBUG=1` | Enable debug logging |
| `-t, --timeout` | `SYNAPSE_TIMEOUT` | Request timeout in ms (default: 30000) |

### Commands

**Health & Status:**
- `health` - Check server health
- `status` - Get sensor status and metrics
- `metrics` - Get Prometheus-formatted metrics

**Entity Management:**
- `entities` - List all tracked entities
- `blocks` - List all block records
- `release <id|ip>` - Release a blocked entity
- `release-all` - Release all blocked entities

**Configuration:**
- `config` - Get system configuration
- `config-set <key=value>...` - Update configuration

**WAF Rules:**
- `rules` - List all WAF rules
- `rule-add <json> [ttl]` - Add a runtime rule
- `rule-remove <id>` - Remove a runtime rule
- `rules-clear` - Clear all runtime rules
- `reload` - Reload rules from file
- `evaluate <method> <url> [headers-json]` - Evaluate request against rules

**Actor Tracking:**
- `actors` - List all tracked actors
- `actor-stats` - Get actor tracking statistics
- `actor-fingerprint <ip> <fp>` - Set actor fingerprint

## Library Usage

```typescript
import { SynapseClient } from 'synapse-client';

const client = new SynapseClient({
  baseUrl: 'http://localhost:3000',
  timeout: 30000,
  debug: false,
});

// Check health
const health = await client.health();
console.log(health.status);

// Get sensor status
const status = await client.getStatus();
console.log(`Total requests: ${status.totalRequests}`);
console.log(`Blocked: ${status.blockedRequests}`);

// List entities
const { entities } = await client.listEntities();
for (const entity of entities) {
  console.log(`${entity.ip}: risk=${entity.risk}, blocked=${entity.blocked}`);
}

// Release a blocked entity
await client.releaseEntity('192.168.1.100');

// Add a runtime rule
await client.addRule({
  name: 'Block test path',
  description: 'Block requests to /test',
  risk: 100,
  blocking: true,
  matches: [{ type: 'uri', match: '/test' }],
}, 3600); // TTL: 1 hour

// Evaluate a request (dry run)
const result = await client.evaluate({
  method: 'GET',
  url: '/api/users?id=1',
});
console.log(`Would block: ${result.wouldBlock}`);
```

## API Reference

### SynapseClient

#### Constructor Options

```typescript
interface SynapseClientOptions {
  baseUrl: string;     // Synapse server URL
  timeout?: number;    // Request timeout in ms (default: 30000)
  debug?: boolean;     // Enable debug logging (default: false)
}
```

#### Methods

| Method | Description |
|--------|-------------|
| `health()` | Check server health |
| `getStatus()` | Get sensor status and metrics |
| `getMetrics()` | Get Prometheus-formatted metrics |
| `listEntities()` | List all tracked entities |
| `listBlocks()` | List all block records |
| `releaseEntity(id)` | Release a blocked entity by ID or IP |
| `releaseAll()` | Release all blocked entities |
| `getConfig()` | Get system configuration |
| `updateConfig(updates)` | Update WAF configuration |
| `listRules()` | List all WAF rules |
| `addRule(rule, ttl?)` | Add a runtime rule |
| `removeRule(id)` | Remove a runtime rule |
| `clearRules()` | Clear all runtime rules |
| `reloadRules()` | Reload rules from file |
| `evaluate(request)` | Evaluate request against rules |
| `listActors()` | List all tracked actors |
| `getActorStats()` | Get actor tracking statistics |
| `setActorFingerprint(ip, fp)` | Set actor fingerprint |

## Development

```bash
# Install dependencies
cd apps/synapse-client
npm install

# Build
npm run build

# Run tests
npm test

# Test with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

## License

MIT
