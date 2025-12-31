# Signal Array Architecture

Signal Array is Signal Horizon's fleet management system that provides centralized visibility and control over distributed edge sensor networks. This document describes the system architecture, components, data flows, and design decisions.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Signal Horizon Cloud                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │  Fleet API   │  │ Synapse Proxy│  │Tunnel Broker │  │ Management  │ │
│  │              │  │              │  │              │  │   API       │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │        │
│  ┌──────┴─────────────────┴─────────────────┴─────────────────┴──────┐ │
│  │                       PostgreSQL + Redis                          │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                    ▲                           ▲
                    │ HTTPS                     │ WSS (outbound from sensors)
                    │                           │
         ┌──────────┴──────────┐     ┌──────────┴──────────┐
         │    Web Dashboard    │     │   Edge Sensors (n)   │
         │    (React SPA)      │     │   ┌─────────────┐   │
         └─────────────────────┘     │   │   Synapse   │   │
                                     │   │   Engine    │   │
                                     │   └─────────────┘   │
                                     └─────────────────────┘
```

## Core Components

### 1. Fleet API (`/api/v1/fleet/`)

Provides CRUD operations and aggregations for sensors and fleet-wide operations.

**Responsibilities**:
- Sensor registration, listing, updates, deletion
- Fleet aggregations and health summaries
- Configuration distribution
- Signal (metrics) ingestion and querying

**Key Files**:
- `api/src/api/routes/fleet.ts` - REST endpoints
- `api/src/services/fleet/` - Business logic

### 2. Synapse Proxy Service

Enables remote introspection and control of sensor-local Synapse engines through WebSocket tunnels.

**Responsibilities**:
- Proxying API calls to sensors
- Caching sensor responses (LRU, max 1000 entries)
- Concurrency control (20 concurrent requests per tenant)
- SSRF protection (path allowlisting)

**Architecture**:

```
┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────┐
│ Client  │────▶│ Synapse API  │────▶│ SynapseProxy │────▶│ Sensor │
│         │     │   Routes     │     │   Service    │     │        │
└─────────┘     └──────────────┘     └──────────────┘     └────────┘
                                            │
                                     ┌──────┴──────┐
                                     │             │
                                  LRU Cache    Semaphore
                                  (1000 max)   (20 concurrent)
```

**Key Files**:
- `api/src/api/routes/synapse.ts` - REST endpoints
- `api/src/services/synapse-proxy.ts` - Proxy implementation

### 3. Tunnel Broker

Manages bidirectional WebSocket tunnels between sensors and Signal Horizon.

**Responsibilities**:
- Sensor connection lifecycle (connect, heartbeat, disconnect)
- User session management (shell, dashboard)
- Message routing between users and sensors
- Heartbeat monitoring (30s interval, 60s timeout)

**Connection Types**:
- **Sensor Tunnels**: Long-lived connections from edge sensors
- **Shell Sessions**: User terminal sessions over WebSocket
- **Dashboard Sessions**: HTTP-over-WebSocket for sensor dashboards

```
┌──────────────────────────────────────────────────────────────────┐
│                        TunnelBroker                              │
│  ┌─────────────────┐              ┌─────────────────────────┐   │
│  │ tunnels: Map    │              │ sessions: Map           │   │
│  │ sensorId →      │              │ sessionId →             │   │
│  │   TunnelSession │              │   UserSession           │   │
│  └─────────────────┘              └─────────────────────────┘   │
│                                                                  │
│  Events: tunnel:connected, tunnel:disconnected,                  │
│          session:started, session:ended, tunnel:message         │
└──────────────────────────────────────────────────────────────────┘
```

**Key Files**:
- `api/src/websocket/tunnel-broker.ts` - Core broker
- `api/src/api/routes/tunnel.ts` - Tunnel REST API

### 4. Management API

Handles API key lifecycle and connectivity testing.

**Responsibilities**:
- API key generation, listing, revocation
- Connectivity health checks
- Usage analytics

**Key Files**:
- `api/src/api/routes/management.ts` - REST endpoints

### 5. Onboarding Service

Manages sensor registration workflow with token-based authentication.

**Responsibilities**:
- Registration token generation and validation
- Pending sensor approval workflow
- Auto-discovery support

**Key Files**:
- `api/src/api/routes/onboarding.ts` - REST endpoints

## Data Flow

### Sensor Registration Flow

```
1. Admin generates registration token
2. Sensor uses token to register
3. Sensor appears in pending queue (or auto-approved)
4. Admin approves sensor
5. Sensor connects WebSocket tunnel
6. Sensor appears in fleet dashboard
```

### Synapse API Call Flow

```
1. User calls POST /api/v1/synapse/:sensorId/rules
2. Synapse routes validate request
3. SynapseProxyService checks:
   a. Tenant authorization
   b. Endpoint allowlist (SSRF protection)
   c. Concurrency limit (semaphore)
   d. Cache (LRU)
4. If cache miss, forward to sensor via TunnelBroker
5. Wait for sensor response (with timeout)
6. Cache successful response
7. Return to user
```

### Shell Session Flow

```
1. User opens shell to sensor
2. TunnelBroker creates UserSession
3. TunnelBroker notifies sensor to spawn PTY
4. Bidirectional data flows:
   - User → TunnelBroker → Sensor (stdin)
   - Sensor → TunnelBroker → User (stdout/stderr)
5. User disconnects or timeout
6. TunnelBroker cleans up session
```

## Security Model

### Authentication Layers

```
┌────────────────────────────────────────────────────────┐
│                    Request Flow                        │
├────────────────────────────────────────────────────────┤
│ 1. TLS termination at load balancer                   │
│ 2. JWT validation (auth middleware)                    │
│ 3. Tenant extraction from token                        │
│ 4. Scope validation (requireScope middleware)          │
│ 5. Sensor ownership verification                       │
└────────────────────────────────────────────────────────┘
```

### SSRF Protection

The Synapse Proxy implements strict SSRF protection:

```typescript
// Allowed Synapse API paths only
const ALLOWED_PATHS = [
  '/status',
  '/entities',
  '/blocks',
  '/rules',
  '/actors',
  '/evaluate',
];

// Blocked patterns
- file://, data://, javascript://
- Internal hosts (localhost, 127.*, 10.*, 172.16-31.*, 192.168.*)
- AWS metadata (169.254.169.254)
```

### Tenant Isolation

Every request is scoped to a tenant:

```typescript
// Middleware extracts tenantId from JWT
const tenantId = req.auth!.tenantId;

// All database queries include tenantId
await prisma.sensor.findMany({
  where: { tenantId }
});

// All tunnel operations verify tenant
if (tunnel.tenantId !== tenantId) {
  throw new Error('Forbidden');
}
```

## Database Schema

### Core Models

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Tenant    │───▶│    Sensor    │───▶│   Signal     │
│              │    │              │    │   (metrics)  │
└──────────────┘    └──────────────┘    └──────────────┘
       │                   │
       │                   ▼
       │            ┌──────────────┐
       │            │  ApiKey      │
       │            └──────────────┘
       ▼
┌──────────────┐
│Registration  │
│   Token      │
└──────────────┘
```

### Key Indexes

```sql
-- Fleet queries
CREATE INDEX idx_sensors_tenant_status ON sensors(tenant_id, status);
CREATE INDEX idx_sensors_tenant_region ON sensors(tenant_id, region);

-- Signal queries
CREATE INDEX idx_signals_sensor_timestamp ON signals(sensor_id, timestamp DESC);
CREATE INDEX idx_signals_tenant_type ON signals(tenant_id, signal_type);

-- Key management
CREATE INDEX idx_apikeys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_apikeys_sensor ON api_keys(sensor_id);
```

## Caching Strategy

### Three-Tier Caching

```
┌─────────────────────────────────────────────────────────┐
│ Tier 1: In-Memory LRU Cache                            │
│ - TTL: 30 seconds                                       │
│ - Max entries: 1000                                     │
│ - Use: Synapse API responses                           │
└─────────────────────────────────────────────────────────┘
                       │ Miss
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 2: Redis Cache                                     │
│ - TTL: 5 minutes                                        │
│ - Use: Fleet aggregations, sensor status               │
└─────────────────────────────────────────────────────────┘
                       │ Miss
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 3: PostgreSQL                                      │
│ - Persistent storage                                    │
│ - Use: All data                                         │
└─────────────────────────────────────────────────────────┘
```

### Cache Invalidation

- **LRU Cache**: TTL-based expiration (30s)
- **Sensor Cache**: Cleared on sensor disconnect
- **Manual Clear**: `/synapse/:sensorId/cache/clear` endpoint

## Performance Considerations

### Concurrency Control

```typescript
// Per-tenant semaphore limits concurrent Synapse requests
const MAX_CONCURRENT = 20;

async execute(request) {
  await this.semaphore.acquire();
  try {
    return await this.forward(request);
  } finally {
    this.semaphore.release();
  }
}
```

### Request Timeouts

| Operation | Timeout |
|-----------|---------|
| Synapse API call | 30 seconds |
| Heartbeat | 60 seconds |
| Shell session idle | 30 minutes |
| Dashboard session | 60 minutes |

### Stale Request Cleanup

Background task cleans up abandoned requests:

```typescript
// Every 60 seconds, remove requests older than 60 seconds
this.cleanupInterval = setInterval(() => {
  const threshold = Date.now() - 60000;
  for (const [id, request] of this.pendingRequests) {
    if (request.createdAt < threshold) {
      request.reject(new Error('Stale request'));
      this.pendingRequests.delete(id);
    }
  }
}, 60000);
```

## Error Handling

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `TUNNEL_NOT_FOUND` | 503 | Sensor not connected |
| `FORBIDDEN` | 403 | Tenant mismatch |
| `TIMEOUT` | 504 | Request timed out |
| `SEND_FAILED` | 503 | WebSocket send failed |
| `SENSOR_ERROR` | 502 | Sensor returned error |
| `INVALID_SENSOR_ID` | 400 | Invalid sensor ID format |
| `ENDPOINT_NOT_ALLOWED` | 403 | SSRF protection triggered |
| `STALE_REQUEST` | 504 | Request expired in queue |

### Error Response Format

```json
{
  "error": "Human-readable message",
  "code": "TUNNEL_NOT_FOUND",
  "retryable": true,
  "suggestions": [
    "Check if sensor is online",
    "Verify sensor ID"
  ]
}
```

## Monitoring

### Metrics

The system exposes Prometheus metrics:

```
# Tunnel metrics
signal_horizon_tunnels_active{tenant="xxx"} 42
signal_horizon_sessions_active{type="shell"} 12
signal_horizon_sessions_active{type="dashboard"} 8

# Synapse proxy metrics
signal_horizon_synapse_requests_total{sensor="xxx",endpoint="rules"} 1234
signal_horizon_synapse_cache_hits_total 5678
signal_horizon_synapse_cache_misses_total 1234

# Performance metrics
signal_horizon_synapse_request_duration_seconds{quantile="0.99"} 0.5
```

### Health Checks

```bash
# API health
GET /health

# Detailed readiness
GET /ready
{
  "database": "ok",
  "redis": "ok",
  "tunnelBroker": "ok"
}
```

## Deployment Topology

### Production Setup

```
                    ┌─────────────┐
                    │   CloudFront│
                    │   (CDN/WAF) │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
       ┌──────▼──────┐          ┌───────▼───────┐
       │  ALB (API)  │          │ ALB (WebSocket)│
       └──────┬──────┘          └───────┬───────┘
              │                         │
     ┌────────┼────────┐      ┌─────────┼─────────┐
     │        │        │      │         │         │
  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐  ┌▼───┐  ┌──▼──┐  ┌──▼──┐
  │API 1│  │API 2│  │API n│  │WS 1│  │WS 2│  │WS n│
  └─────┘  └─────┘  └─────┘  └────┘  └─────┘  └─────┘
     │        │        │        │       │        │
     └────────┴────────┴────────┴───────┴────────┘
                       │
         ┌─────────────┴─────────────┐
         │                           │
    ┌────▼────┐              ┌───────▼───────┐
    │PostgreSQL│              │    Redis      │
    │  (RDS)   │              │ (ElastiCache) │
    └─────────┘              └───────────────┘
```

### Scaling Considerations

- **API servers**: Stateless, scale horizontally
- **WebSocket servers**: Sticky sessions via ALB, scale with sensor count
- **PostgreSQL**: Read replicas for fleet queries
- **Redis**: Cluster mode for high availability

## Design Decisions

### Why Outbound WebSocket Tunnels?

**Problem**: Edge sensors are often behind firewalls without inbound ports.

**Solution**: Sensors connect outbound to Signal Horizon, inverting the traditional SSH model.

**Benefits**:
- No firewall changes required at edge sites
- Works through NAT, proxies, corporate firewalls
- Single egress port (443) for all traffic

### Why LRU Cache with Bounded Size?

**Problem**: Unbounded caching could cause memory exhaustion.

**Solution**: LRU cache with 1000-entry max and 30-second TTL.

**Trade-offs**:
- Bounded memory usage vs. potential cache misses
- Short TTL keeps data fresh vs. more sensor requests

### Why Per-Tenant Semaphores?

**Problem**: One tenant's heavy usage could starve others.

**Solution**: Per-tenant concurrency limits (20 concurrent requests).

**Benefits**:
- Fairness across tenants
- Protection against runaway requests
- Predictable resource usage

## Future Considerations

### Planned Improvements

1. **WebSocket Clustering**: Share tunnel state across WS server instances
2. **Request Priority**: Priority queue for time-sensitive operations
3. **Batch Operations**: Fleet-wide rule deployment in single call
4. **Event Streaming**: Real-time sensor events via SSE/WebSocket

### Potential Optimizations

1. **Request Batching**: Combine multiple Synapse calls
2. **Connection Pooling**: Reuse sensor connections
3. **Edge Caching**: Cache closer to users (CDN)
4. **Compression**: Reduce tunnel bandwidth usage
