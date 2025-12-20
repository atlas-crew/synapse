# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TypeScript client library and CLI for the Synapse (risk-server) API. Provides programmatic access to WAF sensor management, entity tracking, rule management, and actor monitoring.

## Build & Development Commands

```bash
# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run build

# Run tests
npm test

# Test with coverage
npm run test:coverage

# Watch mode for tests
npm run test:watch
```

## Architecture

### File Structure

```
src/
├── index.ts     # Package exports
├── types.ts     # TypeScript interfaces
├── client.ts    # SynapseClient class
└── cli.ts       # CLI entry point
test/
├── client.test.ts  # Client unit tests
└── cli.test.ts     # CLI integration tests
```

### Key Components

**`src/types.ts`** - All TypeScript interfaces
- `SynapseClientOptions` - Client configuration
- Response types for all API endpoints
- `SynapseError` - Custom error class

**`src/client.ts`** - Main API client
- `SynapseClient` - Primary class for API interactions
- HTTP helper methods: `get()`, `post()`, `delete()`, `getText()`
- Automatic timeout handling via `AbortSignal.timeout()`
- Debug logging when `debug: true`

**`src/cli.ts`** - Command-line interface
- Iterator-based argument parsing (no external dependencies)
- Environment variable fallback for all options
- Exit codes: 0 (success), 1 (usage error), 2 (runtime error)
- JSON output mode via `--json` flag

### API Endpoint Mapping

| Client Method | HTTP | Endpoint |
|--------------|------|----------|
| `health()` | GET | `/health` |
| `getStatus()` | GET | `/_sensor/status` |
| `getMetrics()` | GET | `/_sensor/metrics` |
| `listEntities()` | GET | `/_sensor/entities` |
| `listBlocks()` | GET | `/_sensor/blocks` |
| `releaseEntity(id)` | POST | `/_sensor/release` |
| `releaseAll()` | POST | `/_sensor/release-all` |
| `getConfig()` | GET | `/_sensor/system/config` |
| `updateConfig(data)` | POST | `/_sensor/config` |
| `listRules()` | GET | `/_sensor/rules` |
| `addRule(rule, ttl)` | POST | `/_sensor/rules` |
| `removeRule(id)` | DELETE | `/_sensor/rules/:id` |
| `clearRules()` | DELETE | `/_sensor/rules` |
| `reloadRules()` | POST | `/_sensor/reload` |
| `evaluate(req)` | POST | `/_sensor/evaluate` |
| `listActors()` | GET | `/_sensor/actors` |
| `getActorStats()` | GET | `/_sensor/actors/stats` |
| `setActorFingerprint(ip, fp)` | POST | `/_sensor/actors/:ip/fingerprint` |

## Adding New Features

### Adding a New API Method

1. Add response type to `src/types.ts`:
```typescript
export interface NewFeatureResponse {
  // response fields
}
```

2. Add method to `SynapseClient` in `src/client.ts`:
```typescript
async getNewFeature(): Promise<NewFeatureResponse> {
  return this.get<NewFeatureResponse>('/_sensor/new-feature');
}
```

3. Add CLI command handler in `src/cli.ts` switch statement:
```typescript
case 'new-feature': {
  const result = await client.getNewFeature();
  output(result);
  break;
}
```

4. Update help text in `printHelp()` function

5. Add tests in `test/client.test.ts`:
```typescript
describe('getNewFeature', () => {
  it('should return feature data', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ /* mock data */ }),
    });
    const result = await client.getNewFeature();
    expect(result).toBeDefined();
  });
});
```

### Error Handling

All methods throw `SynapseError` on HTTP errors:

```typescript
try {
  await client.health();
} catch (err) {
  if (err instanceof SynapseError) {
    console.error(`HTTP ${err.statusCode}: ${err.response}`);
  }
}
```

### Debug Mode

Enable via constructor option or environment variable:

```typescript
const client = new SynapseClient({
  baseUrl: 'http://localhost:3000',
  debug: true,  // or SYNAPSE_DEBUG=1
});
```

Debug output goes to stderr and includes:
- HTTP method and URL for each request
- Request body (JSON)
- Response status
- First 200 chars of response body

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SYNAPSE_URL` | Server URL (required if not using --url) |
| `SYNAPSE_JSON=1` | Enable JSON output |
| `SYNAPSE_DEBUG=1` | Enable debug logging |
| `SYNAPSE_TIMEOUT` | Request timeout in milliseconds |

## Testing

### Unit Tests

Client tests use vitest with mocked `fetch`:

```typescript
describe('SynapseClient', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });
});
```

### CLI Tests

CLI tests spawn the actual CLI process:

```typescript
function runCli(args: string[], env = {}) {
  return spawnSync('node', [CLI_PATH, ...args], { env: { ...process.env, ...env } });
}
```

## Module System

- **Type**: ESM (ES Modules)
- All imports use `.js` extension
- CLI has shebang: `#!/usr/bin/env node`
- `package.json` specifies `"type": "module"`

## Dependencies

- **No runtime dependencies** - uses native `fetch` (Node 18+)
- Dev dependencies: TypeScript, Vitest, @types/node

## Related Projects

- **risk-server** (`apps/risk-server/`) - The API server this client talks to
- **ac-api-client** (`apps/ac-api-client/`) - Similar client for Atlas Crew API (reference implementation)
