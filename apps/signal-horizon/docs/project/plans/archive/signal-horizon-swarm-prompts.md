# Signal Horizon Swarm: Orchestration Prompts

## Required Specs (Attach to Agents)

Before spawning agents, have these files ready:

| File | Used By |
|------|---------|
| `signal-horizon-fleet-management-spec.md` | Agents 1, 2, 3 |
| `ja4-fingerprinting-spec.md` | Agent 5 |
| `impossible-travel-spec.md` | Agent 5 |
| `ctrlx-refresh.pdf` | Agent 2 |
| `Atlas Crew-Brand-Guidelines.md` | Agent 2 |

---

## Overview

You are orchestrating 6 parallel Claude agents to build Signal Horizon fleet management. Each agent has a specific focus area. Your job is to:

1. Spawn each agent with their task prompt
2. Monitor progress
3. Resolve integration conflicts
4. Merge outputs

**Shared repo structure:**

```
signal-horizon/
├── apps/
│   ├── hub/                    # Backend services (Agent 1)
│   │   ├── src/
│   │   │   ├── services/
│   │   │   ├── protocols/      # (Agent 3)
│   │   │   └── index.ts
│   │   └── prisma/
│   └── ui/                     # Frontend (Agent 2)
│       └── src/
│           ├── pages/
│           ├── components/
│           └── hooks/
├── packages/
│   ├── synapse/                # Rust sensor (Agent 5)
│   │   └── src/
│   └── shared/                 # Shared types
├── tests/                      # (Agent 4)
└── docs/                       # (Agent 6)
```

---

## Agent 1: Backend Services

### Context

You are building the Signal Horizon hub backend services. This is the central control plane that aggregates metrics from sensors, manages configurations, and orchestrates the fleet.

### Reference Documents

**ORCHESTRATOR: Attach these files to this agent's context:**

- `signal-horizon-fleet-management-spec.md` - Full spec (MUST READ FIRST)
- Existing Signal Horizon work in the repo (if any)

### Your Deliverables

1. **FleetAggregator Service** (`apps/hub/src/services/fleet-aggregator.ts`)
   - Real-time metric aggregation from sensor heartbeats
   - Compute fleet-wide stats (total RPS, avg latency, health score)
   - Track sensor online/offline status (60s timeout)
   - Emit aggregated metrics every 5 seconds

2. **ConfigManager Service** (`apps/hub/src/services/config-manager.ts`)
   - Store config templates (production, staging, dev)
   - Track config sync state per sensor
   - Generate config diffs
   - Push configs to sensors via Commander

3. **FleetCommander Service** (`apps/hub/src/services/fleet-commander.ts`)
   - Command queue per sensor
   - Send commands: push_config, push_rules, update, restart, collect_diagnostics
   - Track command status (pending, success, failed)
   - Handle command responses

4. **RuleDistributor Service** (`apps/hub/src/services/rule-distributor.ts`)
   - Track rule sync state per sensor
   - Support rollout strategies: immediate, canary, scheduled
   - Bulk rule push

5. **Prisma Schema** (`apps/hub/prisma/schema.prisma`)
   - Sensor model
   - ConfigTemplate model
   - ConfigSyncState model
   - Command model
   - RuleSyncState model

### Technical Requirements

- TypeScript, strict mode
- Use Zustand for service state (if needed)
- WebSocket integration points for Agent 3
- Export clean interfaces for Agent 4 to test

### Code Style

```typescript
// Use explicit types, no `any`
// Use dependency injection pattern
// Include JSDoc for public methods
// Use descriptive variable names
// Minimal comments - code should be self-documenting
```

### Output Format

Create each file with full implementation. Include imports. No placeholders or TODOs.

---

## Agent 2: Frontend UI

### Context

You are building the Signal Horizon fleet management UI. This is a React application that displays aggregated fleet metrics and allows drill-down to individual sensors.

### Reference Documents

**ORCHESTRATOR: Attach these files to this agent's context:**

- `signal-horizon-fleet-management-spec.md` - Full spec with ASCII mockups (MUST READ FIRST)
- `ctrlx-refresh.pdf` - Signal Array mockups (pages 11-22) for sensor detail views
- `Atlas Crew-Brand-Guidelines.md` (color palette, fonts)

### Your Deliverables

1. **Fleet Overview Page** (`apps/ui/src/pages/fleet/overview.tsx`)
   - Sensor status cards (online, warning, offline counts)
   - Aggregate metrics (total RPS, avg latency, error rate, blocked)
   - Fleet traffic chart (24h)
   - Resource utilization bars
   - Traffic by region
   - Sensor table with status, CPU, mem, RPS, latency

2. **Fleet Health Page** (`apps/ui/src/pages/fleet/health.tsx`)
   - Fleet health score (0-100)
   - Health components breakdown
   - P50/P95/P99 latency
   - Sensors requiring attention list

3. **Sensor Detail Page** (`apps/ui/src/pages/fleet/sensors/[id].tsx`)
   - Tab navigation: Overview, Performance, Network, Processes, Logs, Configuration
   - Embed Signal Array-style views (reference PDF pages 14-19)
   - Remote actions panel

4. **Configuration Manager Page** (`apps/ui/src/pages/fleet/config.tsx`)
   - Config templates grid
   - Sync status table
   - Push config form with sensor selection
   - Recent changes list

5. **Rule Distribution Page** (`apps/ui/src/pages/fleet/rules.tsx`)
   - Fleet rules table with sync status
   - Push rules form with rollout strategy

6. **Fleet Updates Page** (`apps/ui/src/pages/fleet/updates.tsx`)
   - Version distribution chart
   - Sensors requiring update table
   - Bulk update form

7. **Shared Components**
   - `SensorStatusBadge` - Online/Warning/Offline pill
   - `MetricCard` - Stat card with trend indicator
   - `SensorTable` - Reusable sensor list
   - `ResourceBar` - CPU/Memory/Disk progress bar

### Technical Requirements

- React 18 with TypeScript
- Zustand for state management
- TanStack Query for data fetching
- Recharts for charts
- Tailwind CSS
- Atlas Crew color palette: blue #0057B7, magenta #D62598
- Rubik font family

### Code Style

```tsx
// Functional components only
// Use custom hooks for data fetching
// Colocate types with components
// Use Tailwind, no inline styles
// Mobile-responsive (but optimize for large screens - SOC monitors)
```

### Output Format

Create each file with full implementation. Include all imports. Working code, no placeholders.

---

## Agent 3: Protocol & WebSocket

### Context

You are building the sensor communication layer - the WebSocket gateway that handles real-time bidirectional communication between the hub and sensors.

### Reference Documents

**ORCHESTRATOR: Attach these files to this agent's context:**

- `signal-horizon-fleet-management-spec.md` - Protocol section (MUST READ FIRST)

### Your Deliverables

1. **WebSocket Gateway** (`apps/hub/src/protocols/websocket-gateway.ts`)
   - Accept sensor connections with authentication
   - Track connected sensors
   - Route messages to appropriate handlers
   - Handle reconnection gracefully
   - Heartbeat timeout detection (60s)

2. **Heartbeat Handler** (`apps/hub/src/protocols/heartbeat-handler.ts`)
   - Parse SensorHeartbeat messages
   - Update FleetAggregator with new metrics
   - Detect status changes (online → offline)
   - Emit events for status changes

3. **Command Sender** (`apps/hub/src/protocols/command-sender.ts`)
   - Send commands to specific sensors
   - Handle command acknowledgments
   - Retry failed commands
   - Timeout handling

4. **Message Types** (`packages/shared/src/protocol-types.ts`)
   - SensorHeartbeat interface
   - HubMessage types (command, config_update, rules_update, blocklist_update)
   - SensorMessage types (heartbeat, metrics, threat_signal, command_response)
   - CommandResponse interface

5. **Sensor Client** (`packages/synapse/src/horizon-client.ts`)
   - Client-side WebSocket connection
   - Heartbeat sender (every 30s)
   - Command receiver and executor
   - Reconnection with exponential backoff

### Technical Requirements

- Use `ws` package for WebSocket server
- Use `zod` for message validation
- Include connection metrics (connected count, message rate)
- Handle backpressure

### Message Format

```typescript
// All messages are JSON with this envelope
interface Message {
  type: string;
  payload: unknown;
  timestamp: string;
  messageId: string;
}
```

### Output Format

Create each file with full implementation. Include error handling. Production-ready code.

---

## Agent 4: Tests

### Context

You are writing tests for Signal Horizon. Cover unit tests, integration tests, and include mock utilities.

### Your Deliverables

1. **Unit Tests - FleetAggregator** (`tests/unit/fleet-aggregator.test.ts`)
   - Test metric aggregation
   - Test sensor timeout detection
   - Test fleet health calculation

2. **Unit Tests - ConfigManager** (`tests/unit/config-manager.test.ts`)
   - Test config template CRUD
   - Test sync state tracking
   - Test diff generation

3. **Unit Tests - FleetCommander** (`tests/unit/fleet-commander.test.ts`)
   - Test command queuing
   - Test command status updates
   - Test timeout handling

4. **Integration Tests - WebSocket** (`tests/integration/websocket.test.ts`)
   - Test sensor connection
   - Test heartbeat flow
   - Test command round-trip

5. **Mock Sensor** (`tests/mocks/mock-sensor.ts`)
   - Simulates a Synapse sensor
   - Sends heartbeats
   - Responds to commands
   - Configurable behavior (healthy, degraded, slow)

6. **Test Utilities** (`tests/utils/`)
   - Factory functions for test data
   - WebSocket test helpers
   - Database seeding

### Technical Requirements

- Vitest for test runner
- Use `@testing-library/react` for component tests (if any)
- Use `supertest` for API tests
- Aim for >80% coverage on services

### Output Format

Create complete test files. Tests should pass. Include setup/teardown.

---

## Agent 5: Sensor Features (Rust)

### Context

You are implementing new detection features in libsynapse (Rust). These are deterministic detection algorithms that run at wire speed.

### Reference Documents

**ORCHESTRATOR: Attach these files to this agent's context:**

- `impossible-travel-spec.md` - Impossible travel spec (MUST READ FIRST)

### Your Deliverables

1. **Impossible Travel Detector** (`packages/synapse/src/travel/detector.rs`)
   - Haversine distance calculation
   - User login history tracking
   - Speed threshold checking (1000 km/h default)
   - Severity calculation
   - Include tests

2. **GeoIP Integration** (`packages/synapse/src/travel/geoip.rs`)
   - MaxMind GeoLite2 integration
   - LRU cache for lookups
   - Include tests

### Technical Requirements

- Rust 2021 edition for Synapse components
- Lua for nginx/OpenResty module
- Use `dashmap` for concurrent maps
- Use `moka` for caching
- Performance target: <2μs per request for each feature
- Include benchmarks

### Code Style

```rust
// Use explicit error types, no unwrap() in production paths
// Include doc comments on public items
// Use #[inline] judiciously
// Include unit tests in same file
```

### Output Format

Create complete Rust modules. Include Cargo.toml dependencies. Code should compile.

---

## Agent 6: Documentation & Blog

### Context

You are writing documentation and the Part 4 blog post about the AI swarm development methodology.

### Your Deliverables

1. **Part 4 Blog Post** (`docs/blog/part-4-the-swarm.md`)

   Theme: "How I Run an AI Development Team"

   Sections:
   - The swarm methodology (multiple specialized Claudes)
   - Task decomposition (how to split work)
   - Context management (what each agent needs)
   - Review workflow (Claude reviews Claude)
   - Real examples:
     - Signal Horizon built in a day
     - 6 agents reviewing code, catching ClickHouse syntax bugs
     - Outshipping a team while being PIPd
   - The economics (one person + AI swarm vs traditional team)
   - When it works, when it doesn't
   - Tools: Claude Cortex, worktrees, etc.

   Tone: Technical but accessible. Include code snippets. Be honest about limitations.

2. **Signal Horizon API Docs** (`docs/api/signal-horizon.md`)
   - Fleet Overview endpoints
   - Sensor management endpoints
   - Config push endpoints
   - Command endpoints
   - WebSocket protocol docs

3. **Deployment Guide** (`docs/deployment/signal-horizon.md`)
   - Prerequisites
   - Hub deployment
   - Sensor registration
   - Configuration
   - Troubleshooting

4. **README Updates** (`apps/hub/README.md`, `apps/ui/README.md`)
   - Quick start
   - Architecture overview
   - Development setup

### Technical Requirements

- Markdown format
- Include code examples
- Include diagrams (Mermaid)
- Follow existing doc conventions

### Output Format

Create complete documents. Ready to publish.

---

## Orchestration Notes

### Dependency Order

```
Agent 3 (Protocol) ──┐
                     ├──▶ Agent 1 (Backend) ──┐
Agent 5 (Features) ──┘                        ├──▶ Agent 4 (Tests)
                                              │
                     Agent 2 (Frontend) ──────┘
                     
Agent 6 (Docs) - can run in parallel, no deps
```

### Integration Points

1. **Backend ↔ Protocol**: FleetAggregator needs heartbeat data from WebSocket gateway
2. **Backend ↔ Frontend**: Frontend consumes Backend API
3. **Protocol ↔ Sensor**: Sensor client talks to WebSocket gateway
4. **Tests ↔ All**: Tests need interfaces from all components

### Merge Strategy

1. Merge Agent 3 (Protocol) first - defines message types
2. Merge Agent 5 (Features) - independent Rust code
3. Merge Agent 1 (Backend) - uses protocol types
4. Merge Agent 2 (Frontend) - uses backend API
5. Merge Agent 4 (Tests) - tests everything
6. Merge Agent 6 (Docs) - final polish

### Conflict Resolution

If agents produce conflicting interfaces:

1. Protocol types (Agent 3) are source of truth for messages
2. Backend (Agent 1) is source of truth for API
3. Adjust other agents to match

### Progress Tracking

Track each agent's progress:

| Agent | Status | Files Complete | Blockers |
|-------|--------|----------------|----------|
| 1 - Backend | | | |
| 2 - Frontend | | | |
| 3 - Protocol | | | |
| 4 - Tests | | | |
| 5 - Features | | | |
| 6 - Docs | | | |

### Review Checklist

Before merging each agent's output:

- [ ] Types match shared interfaces
- [ ] No `any` types
- [ ] Error handling present
- [ ] Tests pass (Agent 4)
- [ ] Follows code style
- [ ] Imports resolve

---

## Quick Start

1. Give Agent 3 their prompt first (they define the protocol)
2. Give Agent 5 their prompt (independent)
3. Give Agent 6 their prompt (independent)
4. Wait for Agent 3 to complete protocol types
5. Give Agent 1 their prompt with protocol types
6. Give Agent 2 their prompt
7. Give Agent 4 their prompt last (needs all interfaces)
8. Merge in dependency order
9. Run integration tests
10. Ship it

Good luck, main thread. 🫡
