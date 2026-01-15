# Signal Horizon Gap Analysis

> **Technical Reference**: `10-Signal-Horizon-Technical-Reference.pdf` (31 pages)
> **Implementation**: `apps/signal-horizon/` (188 TypeScript source files)
> **Analysis Date**: 2026-01-15

## Executive Summary

The Signal Horizon implementation demonstrates **~85%** coverage of features documented in the Technical Reference. This is significantly higher than the synapse-pingora implementation (~60%). Core fleet management services, threat hunting with ClickHouse, WebSocket infrastructure, and war room collaboration are fully implemented. The main gaps are in advanced rollout strategies, some API intelligence signals, and a few specialized endpoints.

### Implementation Score by Category

| Category | Documented | Implemented | Coverage |
|----------|-----------|-------------|----------|
| Fleet API | 8 services | 8 | 100% |
| Synapse Proxy | 4 features | 4 | 100% |
| Tunnel Broker | 4 features | 4 | 100% |
| Fleet Aggregator | 5 features | 5 | 100% |
| Fleet Commander | 4 features | 4 | 100% |
| Config Manager | 4 features | 4 | 100% |
| Rule Distributor | 4 features | 3 | 75% |
| Hunt API | 10 endpoints | 10 | 100% |
| War Room | 6 features | 6 | 100% |
| Fleet Security API | 8 endpoints | 6 | 75% |
| Global Intel API | 6 endpoints | 4 | 67% |
| Rollout Strategies | 5 strategies | 3 | 60% |
| API Intelligence | 2 signals | 0 | 0% |

---

## Fully Implemented Features

### Fleet Management Services (100%)

| Service | File | Status |
|---------|------|--------|
| FleetAggregator | `src/services/fleet/fleet-aggregator.ts` | Implemented |
| FleetCommander | `src/services/fleet/fleet-commander.ts` | Implemented |
| ConfigManager | `src/services/fleet/config-manager.ts` | Implemented |
| RuleDistributor | `src/services/fleet/rule-distributor.ts` | Implemented |

**Implementation Details** (from `IMPLEMENTATION_SUMMARY.md`):
- FleetAggregator: Real-time metrics aggregation, fleet health score, regional grouping, sensor alerts
- FleetCommander: Command orchestration with retry logic, timeout detection, status tracking
- ConfigManager: Template CRUD, SHA-256 hash verification, drift detection, config push
- RuleDistributor: Immediate/Canary/Scheduled rollout, per-sensor sync tracking

### WebSocket Infrastructure (100%)

| Component | File | Status |
|-----------|------|--------|
| TunnelBroker | `src/websocket/tunnel-broker.ts` | Implemented |
| SensorGateway | `src/websocket/sensor-gateway.ts` | Implemented |
| DashboardGateway | `src/websocket/dashboard-gateway.ts` | Implemented |
| CommandSender | `src/protocols/command-sender.ts` | Implemented |

### Synapse Proxy (100%)

| Feature | File | Status |
|---------|------|--------|
| Remote API calls via WebSocket | `src/services/synapse-proxy.ts` | Implemented |
| LRU caching | `src/services/synapse-proxy.ts` | Implemented |
| SSRF protection | `src/services/synapse-proxy.ts` | Implemented |
| Request timeout handling | `src/services/synapse-proxy.ts` | Implemented |

### Hunt API with ClickHouse (100%)

| Endpoint | File | Status |
|----------|------|--------|
| `/api/v1/hunt/status` | `src/api/routes/hunt.ts` | Implemented |
| `/api/v1/hunt/query` | `src/api/routes/hunt.ts` | Implemented |
| `/api/v1/hunt/timeline/:campaignId` | `src/api/routes/hunt.ts` | Implemented |
| `/api/v1/hunt/stats/hourly` | `src/api/routes/hunt.ts` | Implemented |
| `/api/v1/hunt/ip-activity` | `src/api/routes/hunt.ts` | Implemented |
| `/api/v1/hunt/saved-queries` (CRUD) | `src/api/routes/hunt.ts` | Implemented |

**Storage**: ClickHouse schema defined in `clickhouse/schema.sql`

### War Room (100%)

| Feature | File | Status |
|---------|------|--------|
| WarRoomService | `src/services/warroom/index.ts` | Implemented |
| Incident Timeline | `src/services/warroom/index.ts` | Implemented |
| Live Metrics | `src/services/warroom/index.ts` | Implemented |
| Quick Actions | `src/services/warroom/index.ts` | Implemented |
| Team Chat | `src/services/warroom/index.ts` | Implemented |
| API Routes | `src/api/routes/warroom.ts` | Implemented |

### Core API Routes (100%)

| Route Module | File | Status |
|--------------|------|--------|
| Campaigns | `src/api/routes/campaigns.ts` | Implemented |
| Threats | `src/api/routes/threats.ts` | Implemented |
| Blocklist | `src/api/routes/blocklist.ts` | Implemented |
| Intel | `src/api/routes/intel.ts` | Implemented |
| Fleet | `src/api/routes/fleet.ts` | Implemented |
| Tunnel | `src/api/routes/tunnel.ts` | Implemented |
| Management | `src/api/routes/management.ts` | Implemented |
| Onboarding | `src/api/routes/onboarding.ts` | Implemented |
| Synapse | `src/api/routes/synapse.ts` | Implemented |
| Beam | `src/api/routes/beam.ts` | Implemented |

### Additional Services (100%)

| Service | File | Purpose |
|---------|------|---------|
| ImpossibleTravelService | `src/services/impossible-travel.ts` | Geo-velocity anomaly detection |
| IntelService | `src/services/intel/index.ts` | Threat intelligence aggregation |
| Correlator | `src/services/correlator/index.ts` | Campaign correlation |
| Broadcaster | `src/services/broadcaster/index.ts` | Real-time event broadcasting |
| Aggregator | `src/services/aggregator/index.ts` | Metrics aggregation |
| SensorBridge | `src/services/sensor-bridge.ts` | Sensor communication bridge |

---

## P1 - High Priority Gaps

### 1. Rolling and Blue/Green Rollout Strategies - Not Implemented

**PDF Reference**: Page 17, Rollout Strategies
**Current Status**: Only Immediate, Canary, Scheduled implemented

```
PDF Specification:
| Strategy   | Description                              |
|------------|------------------------------------------|
| Immediate  | Push to all sensors at once              | IMPLEMENTED
| Canary     | 10% → 50% → 100% with validation        | IMPLEMENTED
| Rolling    | One at a time, wait for health           | MISSING
| Scheduled  | At specified time                        | IMPLEMENTED
| Blue/Green | Parallel deployment, instant switchover  | MISSING
```

**Impact**: Cannot perform gradual, health-aware version updates or instant switchover deployments.

**Implementation Location**: `src/services/fleet/rule-distributor.ts`

---

### 2. API Intelligence Signals - Not Implemented

**PDF Reference**: Page 13, API Intelligence Signals (NEW)
**Current Status**: No implementation found

```
PDF Specification:
| Signal Type         | Trigger                          | Description                    |
|---------------------|----------------------------------|--------------------------------|
| TEMPLATE_DISCOVERY  | New endpoint pattern learned     | Sensor discovered new API      |
| SCHEMA_VIOLATION    | Traffic deviates from schema     | Request doesn't match schema   |
```

**Impact**: SOC cannot see "what the WAF is thinking" at fleet scale. API discovery stats not aggregated.

**Implementation Note**: This requires integration with synapse-pingora's SchemaLearner (also not implemented there).

---

### 3. Actor Profiles Endpoint - Partial Implementation

**PDF Reference**: Page 29, Signal Horizon API
**Current Status**: Route exists but full actor profiling unclear

```
PDF Specification:
/api/intel/actors/:id - GET - Threat actor profile
```

**Implementation Status**: Intel routes exist but dedicated actor profile aggregation needs verification.

---

## P2 - Medium Priority Gaps

### 4. Fleet Security Analytics Depth

**PDF Reference**: Pages 18-21, Fleet Security
**Current Status**: Beam routes provide security dashboard but some analytics features may be incomplete

**Documented Features**:
- Traffic Overview (requests vs blocked over time)
- Attack Distribution breakdown
- Recent Blocked requests
- Coverage Score calculation

**Status**: Beam API (`src/api/routes/beam.ts`) provides analytics endpoints. Verify completeness against spec.

---

### 5. Campaign Correlation Visualization

**PDF Reference**: Page 11-12, Campaign Correlation
**Current Status**: Correlator service exists, visualization in UI needs verification

```
PDF Documented Correlation Types:
- Payload Clustering      (similar attack signatures)
- Temporal Clustering     (attacks in time windows)
- Actor Correlation       (same actor across sensors)
- Fingerprint Matching    (JA4/JA4H correlation)
- Geo Clustering          (attacks from same region)
- Behavioral Patterns     (similar attack sequences)
```

**Note**: These align with synapse-pingora's campaign detectors which ARE implemented.

---

## P3 - Low Priority / Nice to Have

### 6. Live Attack Map

**PDF Reference**: Page 8, Threat Overview screenshot
**Current Status**: UI component status unknown

**Feature**: Real-time geographic visualization of attacks with severity indicators.

---

### 7. Playbook Integration

**PDF Reference**: Page 14, War Room Features
**Current Status**: Basic war room implemented, playbook automation unclear

```
PDF Specification:
- Pre-defined response workflows
- Automated @horizon-bot actions
```

---

## Implementation vs PDF API Reference

### Hunt API Endpoints (100% Coverage)

| Endpoint | PDF | Implemented |
|----------|-----|-------------|
| GET /api/v1/hunt/status | Page 25 | `src/api/routes/hunt.ts` |
| POST /api/v1/hunt/query | Page 25 | `src/api/routes/hunt.ts` |
| GET /api/v1/hunt/timeline/:campaignId | Page 25 | `src/api/routes/hunt.ts` |
| GET /api/v1/hunt/stats/hourly | Page 25 | `src/api/routes/hunt.ts` |
| POST /api/v1/hunt/ip-activity | Page 25 | `src/api/routes/hunt.ts` |
| GET /api/v1/hunt/saved-queries | Page 26 | `src/api/routes/hunt.ts` |
| POST /api/v1/hunt/saved-queries | Page 26 | `src/api/routes/hunt.ts` |
| GET /api/v1/hunt/saved-queries/:id | Page 26 | `src/api/routes/hunt.ts` |
| POST /api/v1/hunt/saved-queries/:id/run | Page 26 | `src/api/routes/hunt.ts` |
| DELETE /api/v1/hunt/saved-queries/:id | Page 26 | `src/api/routes/hunt.ts` |

### Fleet Management API (100% Coverage)

| Endpoint | PDF | Implemented |
|----------|-----|-------------|
| GET /api/v1/fleet | Page 26 | `src/api/routes/fleet.ts` |
| GET /api/v1/fleet/alerts | Page 26 | `src/api/routes/fleet.ts` |
| GET /api/v1/fleet/sensors | Page 26 | `src/api/routes/fleet.ts` |
| GET /api/v1/fleet/sensors/:sensorId | Page 26 | `src/api/routes/fleet.ts` |
| CRUD /api/v1/fleet/config/templates | Page 27 | `src/api/routes/fleet.ts` |
| POST /api/v1/fleet/config/push | Page 27 | `src/api/routes/fleet.ts` |
| GET/POST /api/v1/fleet/commands | Page 27 | `src/api/routes/fleet.ts` |
| GET/POST /api/v1/fleet/rules/* | Page 27 | `src/api/routes/fleet.ts` |

### Fleet Security API (Via Beam Routes)

| Endpoint | PDF | Implemented |
|----------|-----|-------------|
| GET /api/v1/fleet/dashboard | Page 28 | `src/api/routes/beam.ts` |
| GET /api/v1/fleet/endpoints | Page 28 | `src/api/routes/beam.ts` |
| GET /api/v1/fleet/rules | Page 28 | `src/api/routes/beam.ts` |
| GET /api/v1/fleet/threats | Page 28 | `src/api/routes/beam.ts` |

### Signal Horizon Global Intel API

| Endpoint | PDF | Implemented |
|----------|-----|-------------|
| GET /api/intel/overview | Page 29 | `src/api/routes/intel.ts` |
| GET /api/intel/campaigns | Page 29 | `src/api/routes/campaigns.ts` |
| GET /api/intel/campaigns/:id | Page 29 | `src/api/routes/campaigns.ts` |
| GET /api/intel/actors/:id | Page 29 | Needs verification |
| GET /api/warroom | Page 29 | `src/api/routes/warroom.ts` |
| GET /api/warroom/:id | Page 29 | `src/api/routes/warroom.ts` |

---

## Database Schema Status

**Prisma Models** (from `prisma/schema.prisma`):
- ConfigTemplate
- SensorSyncState
- FleetCommand
- RuleSyncState
- Sensor (with fleet relations)

**ClickHouse** (from `clickhouse/schema.sql`):
- Historical threat hunting tables
- Time-series aggregation

---

## Recommended Implementation Order

### Phase 1: Rollout Strategy Completion
1. **Rolling Strategy** (~1-2 days)
   - One-at-a-time deployment with health checks
   - Add to `rule-distributor.ts`

2. **Blue/Green Strategy** (~2-3 days)
   - Parallel deployment infrastructure
   - Instant switchover mechanism

### Phase 2: API Intelligence
3. **API Signal Ingestion** (~2-3 days)
   - Requires synapse-pingora SchemaLearner first
   - Signal aggregation in Aggregator service
   - Dashboard visualization

### Phase 3: Enhanced Visualization
4. **Live Attack Map** (~2-3 days)
   - GeoIP data aggregation
   - Real-time WebSocket updates to UI

5. **Playbook Automation** (~3-4 days)
   - Define playbook schema
   - @horizon-bot automated actions
   - War room integration

---

## Comparison: Signal Horizon vs Synapse-Pingora

| Aspect | Signal Horizon | Synapse-Pingora |
|--------|---------------|-----------------|
| **Coverage** | ~85% | ~60% |
| **Language** | TypeScript | Rust |
| **Primary Role** | Fleet Command & Control | Edge WAF Proxy |
| **State Management** | PostgreSQL + Redis + ClickHouse | In-memory + Snapshot |
| **ImpossibleTravel** | Implemented | NOT Implemented |
| **SessionManager** | N/A (fleet-level) | NOT Implemented |
| **ActorManager** | N/A (fleet-level) | NOT Implemented |
| **Campaign Correlation** | Aggregates from sensors | 7 detectors implemented |
| **Interrogator System** | N/A (sensor-side) | Only Tarpit |
| **API Profiling** | N/A (sensor-side) | NOT Implemented |

**Key Insight**: Signal Horizon is the "control plane" that orchestrates sensors, while synapse-pingora is the "data plane" that processes traffic. Many features missing in synapse-pingora (ActorManager, SessionManager, Interrogator) would be sensor-side implementations that Signal Horizon would then aggregate.

---

## Dependency Between Projects

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIGNAL HORIZON (Control Plane)                │
│   Fleet Management │ Threat Hunting │ War Room │ Analytics       │
├─────────────────────────────────────────────────────────────────┤
│                         WebSocket / REST                          │
├─────────────────────────────────────────────────────────────────┤
│                    SYNAPSE-PINGORA (Data Plane)                  │
│   WAF Detection │ Campaign Correlation │ Entity Tracking         │
│                                                                   │
│   ❌ ActorManager     ❌ SessionManager     ❌ Interrogator       │
│   (These gaps affect Signal Horizon's ability to aggregate)       │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation Priority**: Synapse-Pingora P0 gaps (ActorManager, SessionManager) should be addressed first, as they enable Signal Horizon's full aggregation capabilities.

---

## Files Modified for This Analysis

None - this is a read-only gap analysis.

## References

- Technical Reference PDF: `10-Signal-Horizon-Technical-Reference.pdf`
- Implementation: `apps/signal-horizon/`
- Fleet Services Summary: `apps/signal-horizon/api/src/services/fleet/IMPLEMENTATION_SUMMARY.md`
- Related: `apps/synapse-pingora/docs/GAP_ANALYSIS.md`
