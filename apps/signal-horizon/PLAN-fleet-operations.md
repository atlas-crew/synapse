# Fleet Operations Implementation Plan

## Overview

Build a centralized management console for ALL sensors in Signal Horizon. This enables operators to manage sensors from one place without ever needing local access again.

**Product Name**: Signal Array (Fleet Management)

## User Decisions
- **Priority**: Overview First → Fleet Overview → All Sensors → Sensor Details → Remote Access → Management
- **Remote Access**: WebSocket Tunnel (sensors establish outbound WS, no open ports needed)
- **Data Source**: Hybrid (WebSocket heartbeats for fleet-wide, Synapse client for deep introspection)
- **Onboarding**: Configurable (support agent script, manual registration, AND auto-discovery)

## Reference Mockup
`/Users/nferguson/Library/CloudStorage/OneDrive-Atlas CrewNetworks/Skunkworks/edge intelligence/mockups/signal_array.pdf`

---

## Phase 1: Fleet Overview & Sensor List (Foundation)

### 1.1 Database Schema Updates
**File**: `api/prisma/schema.prisma`

```prisma
// Enhance Sensor model
model Sensor {
  // ... existing fields ...

  // New fields for Signal Array
  publicIp         String?          // External IP for connectivity
  privateIp        String?          // Internal/VPC IP
  os               String?          // "Ubuntu 22.04 LTS"
  kernel           String?          // "5.15.0-89-generic"
  architecture     String?          // "x86_64"
  instanceType     String?          // "c5.xlarge"
  lastBoot         DateTime?        // Last reboot time
  uptime           Int?             // Seconds since boot

  // Tunnel/Remote Access
  tunnelActive     Boolean          @default(false)
  tunnelSessionId  String?          // Active tunnel session

  // Onboarding
  registrationMethod RegistrationMethod @default(MANUAL)
  registrationToken  String?        // One-time registration token
  approvalStatus     ApprovalStatus @default(APPROVED)
  approvedAt         DateTime?
  approvedBy         String?

  // Relations
  apiKeys          SensorApiKey[]
  diagnosticBundles DiagnosticBundle[]
  updateHistory    SensorUpdate[]
}

enum RegistrationMethod {
  MANUAL          // Admin created in UI
  AGENT_SCRIPT    // Auto-registered via install script
  AUTO_DISCOVERY  // Announced, pending approval
}

enum ApprovalStatus {
  PENDING
  APPROVED
  REJECTED
}

model SensorApiKey {
  id          String    @id @default(cuid())
  name        String    // "prod-us-east-primary"
  keyHash     String    // SHA-256 of actual key
  keyPrefix   String    // "sk_****8f2k" for display
  sensorId    String
  sensor      Sensor    @relation(fields: [sensorId], references: [id], onDelete: Cascade)
  createdAt   DateTime  @default(now())
  expiresAt   DateTime?
  lastUsedAt  DateTime?
  status      KeyStatus @default(ACTIVE)
  permissions String[]  // ["read_metrics", "write_logs", "admin"]
  createdBy   String?

  @@index([sensorId])
  @@index([keyHash])
}

enum KeyStatus {
  ACTIVE
  EXPIRED
  REVOKED
}

model DiagnosticBundle {
  id          String   @id @default(cuid())
  sensorId    String
  sensor      Sensor   @relation(fields: [sensorId], references: [id], onDelete: Cascade)
  requestedAt DateTime @default(now())
  completedAt DateTime?
  status      String   @default("pending") // pending, collecting, complete, failed
  includes    String[] // ["system_info", "process_list", "network_connections", "logs"]
  downloadUrl String?
  expiresAt   DateTime?
  notes       String?

  @@index([sensorId])
}

model SensorUpdate {
  id            String   @id @default(cuid())
  sensorId      String
  sensor        Sensor   @relation(fields: [sensorId], references: [id], onDelete: Cascade)
  fromVersion   String
  toVersion     String
  status        String   // scheduled, in_progress, completed, failed, rolled_back
  scheduledFor  DateTime?
  startedAt     DateTime?
  completedAt   DateTime?
  rollbackAvailable Boolean @default(true)
  logs          String?

  @@index([sensorId])
}
```

### 1.2 API Routes - Fleet Overview
**File**: `api/src/api/routes/fleet.ts` (extend existing)

New endpoints:
```typescript
// Fleet Overview
GET  /api/v1/fleet/overview              // Aggregated fleet metrics + regional breakdown
GET  /api/v1/fleet/regions               // Region-by-region health summary
GET  /api/v1/fleet/alerts                // Active alerts (existing, extend)

// Sensor List (enhanced)
GET  /api/v1/fleet/sensors               // Paginated with enhanced filtering
     ?status=online|warning|offline
     ?region=us-east-1
     ?version=4.2.1
     ?search=prod
     ?sort=name|status|cpu|memory|rps
     ?page=1&limit=25

// Bulk Operations
POST /api/v1/fleet/sensors/bulk          // Bulk actions on selected sensors
     { action: "restart" | "update" | "sync_config", sensorIds: [...] }
```

### 1.3 UI Pages - Fleet Overview
**Files**: `ui/src/pages/fleet/`

#### FleetOverviewPage.tsx
- **Top Stats Cards**: Sensors Online, Needs Attention, Offline, Total RPS
- **Quick Actions**: Run Diagnostics, View Access Logs, Configure Sensors, Test Connectivity
- **Recent Alerts**: List with sensor name, alert type, time ago
- **Fleet Distribution**: Bar chart by region (online/warning/offline)
- **Sensor Fleet Table**: Sortable, searchable, with health metrics inline

#### AllSensorsPage.tsx (enhanced)
- Full-featured data table with:
  - Status badge (online/warning/offline)
  - Health metrics (CPU, MEM, REQ/S inline)
  - Version with update indicator
  - Region tag
  - Last check-in
  - Actions menu (view, SSH, diagnostics, restart)
- Bulk selection with bulk actions toolbar
- Advanced filtering panel
- Pagination with configurable page size

### 1.4 UI Components
**Files**: `ui/src/components/fleet/`

```
SensorTable.tsx         (enhance existing)
FleetStatsCards.tsx     (new - top stats row)
FleetAlerts.tsx         (new - recent alerts list)
FleetDistributionChart.tsx (new - region bar chart)
SensorStatusBadge.tsx   (enhance existing)
SensorQuickActions.tsx  (new - action buttons row)
BulkActionsToolbar.tsx  (new - selected sensors actions)
```

---

## Phase 2: Sensor Detail Pages

### 2.1 Sensor Detail - Overview Tab
**File**: `ui/src/pages/fleet/SensorDetailPage.tsx`

Layout matching mockup page 2:
- **Header**: Sensor name, ID, region, status badge, action buttons (Refresh, SSH, Run Diagnostics, Configure)
- **Resource Cards**: CPU%, Memory%, Disk%, REQ/SEC, Latency P99, Uptime
- **Tab Navigation**: Overview, Performance, Network, Processes, Logs, Configuration
- **System Information Panel**: Hostname, Sensor ID, Version, OS, Kernel, Architecture, IPs, Region, Instance Type, Last Boot, Last Check-in
- **Connection Status Panel**: Cloud connection, latency, uptime, reconnects
- **Key Processes Panel**: nginx, atlascrew-agent, atlascrew-collector, etc.
- **Quick Actions Panel**: Restart Services, Clear Logs, Update Sensor, Test Connectivity, Restart Sensor

### 2.2 Sensor Detail - Performance Tab
**File**: `ui/src/pages/fleet/SensorPerformancePage.tsx`

Matching mockup page 3:
- **Top Stats**: CPU Usage, Memory Usage, Disk Usage, Load Average
- **CPU Utilization Chart**: Per-core breakdown over time
- **Memory Utilization Chart**: Used/Cached/Free over time
- **System Metrics**: Context Switches, Interrupts, Uptime, File Descriptors, Threads
- **Disk I/O Panel**: Read/Write Throughput, IOPS, I/O Wait
- **Performance Benchmarks Table**: Request Processing Latency, Rule Evaluation Time, SSL Handshake, etc.
- **Disk I/O Over Time Chart**
- **Request Latency Distribution Chart**

### 2.3 Sensor Detail - Network Tab
**File**: `ui/src/pages/fleet/SensorNetworkPage.tsx`

Matching mockup page 1:
- **Top Stats**: Inbound Traffic, Outbound Traffic, Active Connections, Packets/Sec
- **Network Traffic Chart**: Inbound/Outbound Mbps over time
- **Network Interfaces Panel**: eth0, eth1, lo, etc. with RX/AC rates
- **Active Connections Table**: Protocol, Local/Remote Address, State, PID/Program, Duration
- **DNS Configuration**: Primary/Secondary/Fallback with latency
- **Routing Table**
- **Firewall Rules (iptables)**: With hit counts

### 2.4 Sensor Detail - Processes Tab
**File**: `ui/src/pages/fleet/SensorProcessesPage.tsx`

Matching mockup page 4:
- **Top Stats**: Total Processes, Total Threads, System Services healthy, Open Files
- **Running Processes Table**: PID, Name, User, CPU%, MEM%, Status, Actions (view, restart, kill)
- **Atlas Crew Services Panel**: atlascrew-waf, atlascrew-agent, atlascrew-collector, etc. with status
- **System Services Panel**: nginx, postgresql, redis, unbound
- **Process CPU Over Time Chart**

### 2.5 Sensor Detail - Logs Tab
**File**: `ui/src/pages/fleet/SensorLogsPage.tsx`

Matching mockup page 8:
- **Diagnostic Actions**: Connectivity Test, Health Check, Disk Analysis, Process Inspector
- **Log Tabs**: Access Logs, Error Logs, System Logs, Diagnostics, Request Logs
- **Log Viewer**: Filterable, searchable, with timestamp, method, path, status, size, duration
- **Latest Diagnostic Results**: Checklist of passed/warning/failed checks
- **Request Diagnostic Data Form**: Time range, log types, include options, notes

### 2.6 Sensor Detail - Configuration Tab
**File**: `ui/src/pages/fleet/SensorConfigPage.tsx`

Matching mockup page 6:
- **Sensor Selector**: Dropdown to switch sensors
- **Config Tabs**: General Settings, Kernel Parameters, Nginx Configuration, TLS/SSL, Change History
- **General Settings Panel**: Toggles for Auto-Updates, Verbose Logging, Health Check Reporting, etc.
- **Network Settings Panel**: Upstream Timeout, Max Connections, Keepalive, Buffer Size
- **Kernel Parameters Panel**: sysctl values with edit capability
- **Nginx Configuration Editor**: Monaco editor with syntax highlighting, validate/copy/download/upload
- **Recent Configuration Changes**: Audit log with revert capability

### 2.7 API Routes - Sensor Details
**File**: `api/src/api/routes/sensors.ts` (new file for deep sensor ops)

```typescript
// System Information (from Synapse client)
GET  /api/v1/sensors/:id/system          // OS, kernel, IPs, etc.
GET  /api/v1/sensors/:id/performance     // CPU, memory, disk detailed metrics
GET  /api/v1/sensors/:id/network         // Interfaces, connections, traffic
GET  /api/v1/sensors/:id/processes       // Running processes, services
GET  /api/v1/sensors/:id/logs            // Log entries with filtering
     ?type=access|error|system
     ?since=2024-01-15T00:00:00Z
     ?limit=100

// Configuration
GET  /api/v1/sensors/:id/config          // Full configuration
PUT  /api/v1/sensors/:id/config          // Update configuration
GET  /api/v1/sensors/:id/config/history  // Configuration change history
POST /api/v1/sensors/:id/config/revert   // Revert to previous config

// Diagnostics
POST /api/v1/sensors/:id/diagnostics/run // Run diagnostic checks
GET  /api/v1/sensors/:id/diagnostics     // Get diagnostic results
POST /api/v1/sensors/:id/diagnostics/bundle // Request diagnostic bundle

// Actions
POST /api/v1/sensors/:id/actions/restart        // Restart sensor
POST /api/v1/sensors/:id/actions/restart-service // Restart specific service
POST /api/v1/sensors/:id/actions/clear-logs     // Clear log files
POST /api/v1/sensors/:id/actions/test-connectivity // Run connectivity tests
```

---

## Phase 3: Remote Access (WebSocket Tunnel)

### 3.1 Tunnel Architecture

```
┌──────────────────┐     Outbound WS      ┌──────────────────┐
│                  │ ──────────────────── │                  │
│  Edge Sensor     │                      │  Signal Horizon  │
│                  │ <─── Tunnel Traffic  │     (Cloud)      │
│  - Shell         │                      │                  │
│  - Dashboard     │                      │  - Tunnel Broker │
│  - Synapse API   │                      │  - Web Terminal  │
└──────────────────┘                      └──────────────────┘
```

Sensor connects outbound (no inbound ports needed):
1. Sensor establishes WebSocket to Signal Horizon `/ws/tunnel`
2. Signal Horizon assigns tunnel session ID
3. User requests shell/dashboard through Signal Horizon
4. Signal Horizon routes request through tunnel to sensor
5. Sensor proxies to local service (bash, dashboard, Synapse API)

### 3.2 Sensor-Side Tunnel Agent
**File**: (sensor codebase - agent component)

The sensor runs a tunnel agent that:
- Maintains persistent WebSocket to Signal Horizon
- Authenticates with sensor API key
- Handles tunnel commands:
  - `shell:start` - Start shell session (PTY)
  - `shell:input` - Stdin to shell
  - `shell:resize` - Terminal resize
  - `dashboard:proxy` - Proxy HTTP to local dashboard
  - `synapse:proxy` - Proxy to Synapse API

### 3.3 Signal Horizon Tunnel Broker
**File**: `api/src/websocket/tunnel-broker.ts`

```typescript
// Tunnel broker manages:
// 1. Sensor tunnel connections (outbound from sensors)
// 2. User session connections (dashboard users wanting shell/dashboard)
// 3. Routing between them

interface TunnelSession {
  sensorId: string;
  tenantId: string;
  socket: WebSocket;
  capabilities: ('shell' | 'dashboard' | 'synapse')[];
  connectedAt: Date;
}

interface UserSession {
  userId: string;
  tenantId: string;
  sensorId: string;
  type: 'shell' | 'dashboard';
  tunnelSession: TunnelSession;
}

class TunnelBroker {
  private sensorTunnels: Map<string, TunnelSession>;
  private userSessions: Map<string, UserSession>;

  // Handle incoming sensor tunnel connection
  handleSensorConnect(ws: WebSocket, sensorId: string): void;

  // Handle user requesting shell access
  startShellSession(userId: string, sensorId: string): ShellSession;

  // Handle user requesting dashboard proxy
  startDashboardProxy(userId: string, sensorId: string): DashboardProxy;

  // Route traffic between user and sensor
  routeTraffic(sessionId: string, data: Buffer): void;
}
```

### 3.4 Web Terminal Component
**File**: `ui/src/components/fleet/WebTerminal.tsx`

Using xterm.js for browser-based terminal:
```typescript
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';

interface WebTerminalProps {
  sensorId: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
}

// Features:
// - Full PTY support (colors, cursor movement, etc.)
// - Copy/paste
// - Resize handling
// - Reconnect on disconnect
// - Session recording (optional)
```

### 3.5 Embedded Dashboard Viewer
**File**: `ui/src/components/fleet/EmbeddedDashboard.tsx`

Two approaches:
1. **Proxy Mode**: Signal Horizon proxies dashboard HTML/assets through tunnel
2. **iframe Mode**: For sensors with direct network access (fallback)

```typescript
interface EmbeddedDashboardProps {
  sensorId: string;
  tunnelMode: boolean; // Use tunnel proxy vs direct iframe
}

// The embedded dashboard shows the sensor's standalone Synapse dashboard
// - All metrics and controls available
// - Actions are proxied through tunnel
// - Real-time updates via WebSocket through tunnel
```

### 3.6 API Routes - Remote Access
**File**: `api/src/api/routes/tunnel.ts`

```typescript
// Tunnel Management
GET  /api/v1/tunnel/status/:sensorId     // Check if tunnel is active
POST /api/v1/tunnel/shell/:sensorId      // Start shell session
POST /api/v1/tunnel/dashboard/:sensorId  // Start dashboard proxy session

// WebSocket endpoints (handled separately)
WS   /ws/tunnel/sensor                   // Sensor tunnel connection
WS   /ws/tunnel/user/:sessionId          // User shell/dashboard session
```

---

## Phase 4: Fleet Management Pages

### 4.1 Connectivity Page
**File**: `ui/src/pages/fleet/ConnectivityPage.tsx`

Matching mockup page 7:
- **Top Stats**: Connected, Disconnected, Avg Latency, Uptime (30D)
- **Atlas Crew Cloud Endpoints**: API Gateway, Telemetry Collector, Rules Engine with status/latency
- **Connectivity Tests**: Ping Test, DNS Resolution, TLS Handshake, Traceroute
- **Sensor Connectivity Status Table**: Per-sensor connection status, latency, heartbeat, reconnects, packet loss
- **Latency Trend Chart**: 24h latency over time
- **Connection Events Chart**: Weekly reconnection events

### 4.2 Health Metrics Page
**File**: `ui/src/pages/fleet/HealthMetricsPage.tsx`

Matching mockup page 9:
- **Fleet Health Score**: 0-100 with status text
- **Resource Breakdown**: CPU, Memory, Disk, Connectivity percentages
- **Top Stats**: Total Requests, Average Latency, Error Rate with trends
- **Resource Usage Trend Chart**: CPU/Memory/Disk over time
- **Sensor Health Table**: Per-sensor health with metrics
- **Active Health Alerts**: Current alerts with severity

### 4.3 Sensor Keys Page
**File**: `ui/src/pages/fleet/SensorKeysPage.tsx`

Matching mockup page 10:
- **Top Stats**: Total Keys, Active Keys, Expired Keys, Expiring Soon
- **API Keys Table**: Name, Sensor, Key ID, Created, Expires, Status, Last Used, Actions
- **Generate New Key Form**: Name, Associated Sensor, Expiration, Permissions
- **Recent Activity**: Key generated, rotated, revoked events

### 4.4 Updates Page
**File**: `ui/src/pages/fleet/UpdatesPage.tsx`

Matching mockup page 11:
- **Latest Version Banner**: Version number, release date, release notes button
- **Update Stats**: Up to Date, Updates Available, Scheduled Updates, Failed Updates
- **Update Schedule Policy**: Manual, Scheduled Maintenance, Auto-Update selector
- **Sensors Requiring Update Table**: Sensor, Current Version, Target Version, Status, Actions
- **Version Release Notes**: Security updates, new features, bug fixes
- **Recent Update Activity**: Timeline of updates

### 4.5 API Routes - Management
**File**: `api/src/api/routes/management.ts`

```typescript
// API Keys
GET    /api/v1/fleet/keys                    // List all API keys
POST   /api/v1/fleet/keys                    // Generate new key
DELETE /api/v1/fleet/keys/:keyId             // Revoke key
POST   /api/v1/fleet/keys/:keyId/rotate      // Rotate key
POST   /api/v1/fleet/keys/rotate-all         // Rotate all keys for a sensor

// Updates
GET    /api/v1/fleet/updates/available       // Check for updates
GET    /api/v1/fleet/updates/history         // Update history
POST   /api/v1/fleet/updates/schedule        // Schedule updates
POST   /api/v1/fleet/updates/cancel          // Cancel scheduled update
GET    /api/v1/fleet/updates/releases        // Get release notes

// Connectivity
GET    /api/v1/fleet/connectivity            // Fleet-wide connectivity status
POST   /api/v1/fleet/connectivity/test       // Run connectivity tests
GET    /api/v1/fleet/connectivity/history    // Historical connectivity data
```

---

## Phase 5: Sensor Onboarding

### 5.1 Onboarding Methods

#### Method 1: Agent Install Script
```bash
# User gets a one-liner from Signal Horizon UI
curl -fsSL https://signal-horizon.example.com/install.sh | \
  REGISTRATION_TOKEN=tok_abc123 \
  HORIZON_URL=wss://signal-horizon.example.com \
  bash

# Script does:
# 1. Downloads sensor agent
# 2. Registers with Signal Horizon using token
# 3. Receives API key
# 4. Starts services
# 5. Establishes tunnel
```

#### Method 2: Manual Registration
```
1. Admin creates sensor in UI with name, region, etc.
2. System generates API key
3. Admin copies API key to sensor configuration
4. Sensor connects with key
5. Connection verified in UI
```

#### Method 3: Auto-Discovery
```
1. Sensor configured with tenant ID only (no specific API key)
2. Sensor announces itself to Signal Horizon
3. Announcement appears in "Pending Sensors" queue
4. Admin reviews and approves/rejects
5. On approval, API key generated and sent to sensor
6. Sensor upgrades connection to authenticated
```

### 5.2 Onboarding UI
**File**: `ui/src/pages/fleet/OnboardingSensorPage.tsx`

- **Deploy Sensor Button** in Fleet Overview
- **Deployment Method Selector**: Agent Script, Manual, Auto-Discovery instructions
- **Agent Script Generator**: Select region, generate script with embedded token
- **Manual Setup Instructions**: Step-by-step with config snippets
- **Pending Sensors Queue**: For auto-discovery approvals

### 5.3 API Routes - Onboarding
**File**: `api/src/api/routes/onboarding.ts`

```typescript
// Registration Tokens
POST /api/v1/fleet/onboarding/token         // Generate registration token
GET  /api/v1/fleet/onboarding/tokens        // List active tokens
DELETE /api/v1/fleet/onboarding/token/:id   // Revoke token

// Auto-Discovery
GET  /api/v1/fleet/onboarding/pending       // List pending sensor registrations
POST /api/v1/fleet/onboarding/approve/:id   // Approve pending sensor
POST /api/v1/fleet/onboarding/reject/:id    // Reject pending sensor

// Install Script
GET  /api/v1/fleet/onboarding/install.sh    // Generate install script
```

### 5.4 Sensor Registration Flow
**File**: `api/src/websocket/sensor-registration.ts`

```typescript
// Handle sensor registration attempts
async function handleSensorRegistration(ws: WebSocket, message: RegistrationMessage) {
  if (message.type === 'register_with_token') {
    // Validate one-time token
    // Create sensor record
    // Generate API key
    // Return credentials
    // Upgrade to authenticated connection
  } else if (message.type === 'announce') {
    // Validate tenant ID
    // Create pending registration
    // Notify admins
    // Keep connection in limbo until approved
  }
}
```

---

## Phase 6: Synapse Client Integration

### 6.1 Synapse Proxy Service
**File**: `api/src/services/synapse-proxy.ts`

```typescript
import { SynapseClient } from '@atlascrew/synapse-client';

class SynapseProxyService {
  // Route requests through tunnel to sensor's Synapse API
  async proxyRequest(
    sensorId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'DELETE',
    body?: unknown
  ): Promise<unknown>;

  // High-level methods using Synapse client
  async getSensorStatus(sensorId: string): Promise<SensorStatus>;
  async listEntities(sensorId: string): Promise<Entity[]>;
  async listBlocks(sensorId: string): Promise<Block[]>;
  async releaseEntity(sensorId: string, entityId: string): Promise<void>;
  async listRules(sensorId: string): Promise<Rule[]>;
  async addRule(sensorId: string, rule: Rule, ttl?: number): Promise<void>;
  async listActors(sensorId: string): Promise<Actor[]>;
  async evaluateRequest(sensorId: string, request: EvalRequest): Promise<EvalResult>;
}
```

### 6.2 Real-time Metrics Aggregation
- Continue using existing WebSocket heartbeats for fleet-wide metrics
- Use Synapse proxy for detailed sensor introspection on-demand
- Cache Synapse responses with short TTL to reduce tunnel traffic

---

## Implementation Order

### Sprint 1: Foundation (Week 1-2)
1. [ ] Database schema migration for enhanced sensor fields
2. [ ] Fleet overview API endpoint
3. [ ] FleetOverviewPage UI with stats and charts
4. [ ] Enhanced sensor table with filtering
5. [ ] Bulk operations API and UI

### Sprint 2: Sensor Details (Week 3-4)
1. [ ] Sensor detail page shell with tab navigation
2. [ ] Overview tab with system info and resources
3. [ ] Performance tab with charts
4. [ ] Network tab with connections
5. [ ] Processes tab with services

### Sprint 3: Logs & Configuration (Week 5)
1. [ ] Logs tab with viewer
2. [ ] Configuration tab with editor
3. [ ] Diagnostic bundle request flow
4. [ ] Configuration change history

### Sprint 4: Remote Access (Week 6-7)
1. [ ] Tunnel broker WebSocket server
2. [ ] Sensor-side tunnel agent protocol
3. [ ] Web terminal component (xterm.js)
4. [ ] Embedded dashboard proxy

### Sprint 5: Management Pages (Week 8)
1. [ ] Connectivity page
2. [ ] Health metrics page
3. [ ] Sensor keys page
4. [ ] Updates page

### Sprint 6: Onboarding (Week 9)
1. [ ] Registration token system
2. [ ] Agent install script generator
3. [ ] Auto-discovery flow
4. [ ] Pending sensors queue

### Sprint 7: Polish & Testing (Week 10)
1. [ ] End-to-end testing
2. [ ] Performance optimization
3. [ ] Documentation
4. [ ] UI polish and accessibility

---

## Technical Decisions

### State Management
- **TanStack Query**: For server state (sensors, metrics, logs)
- **Zustand**: For UI state (selections, filters, preferences)

### Charts
- **Recharts**: For time-series charts (traffic, CPU, memory)
- Consistent styling with existing Signal Horizon charts

### Terminal
- **xterm.js**: Browser terminal emulator
- **xterm-addon-fit**: Auto-resize
- **xterm-addon-web-links**: Clickable URLs

### Routing
- React Router with nested routes for sensor detail tabs:
```
/fleet                          # Fleet Overview
/fleet/sensors                  # All Sensors
/fleet/sensors/:id              # Sensor Detail (Overview tab)
/fleet/sensors/:id/performance  # Performance tab
/fleet/sensors/:id/network      # Network tab
/fleet/sensors/:id/processes    # Processes tab
/fleet/sensors/:id/logs         # Logs tab
/fleet/sensors/:id/config       # Configuration tab
/fleet/connectivity             # Connectivity Page
/fleet/health                   # Health Metrics Page
/fleet/keys                     # Sensor Keys Page
/fleet/updates                  # Updates Page
/fleet/onboarding               # Deploy New Sensor
```

### WebSocket Protocol
Extend existing sensor gateway to support tunnel commands:
```typescript
type TunnelMessage =
  | { type: 'tunnel:connect'; sensorId: string }
  | { type: 'tunnel:shell:start'; sessionId: string }
  | { type: 'tunnel:shell:input'; sessionId: string; data: string }
  | { type: 'tunnel:shell:output'; sessionId: string; data: string }
  | { type: 'tunnel:shell:resize'; sessionId: string; cols: number; rows: number }
  | { type: 'tunnel:dashboard:request'; sessionId: string; request: ProxyRequest }
  | { type: 'tunnel:dashboard:response'; sessionId: string; response: ProxyResponse }
```

---

## Success Metrics

1. **Onboarding Time**: New sensor connected < 5 minutes
2. **Remote Access Latency**: Shell keystroke RTT < 100ms
3. **Fleet Overview Load**: < 2 seconds for 100+ sensors
4. **Sensor Detail Load**: < 1 second for any tab
5. **Tunnel Reliability**: 99.9% uptime for established tunnels

---

## Dependencies

### New npm packages (UI)
- `xterm` - Terminal emulator
- `xterm-addon-fit` - Terminal sizing
- `xterm-addon-web-links` - Clickable links
- `@monaco-editor/react` - Config editor (if not already present)

### Existing packages to leverage
- `recharts` - Already in use
- `@tanstack/react-query` - Already in use
- `zustand` - Already in use
- `synapse-client` - In monorepo

---

## Open Questions

1. **Session Recording**: Should we record terminal sessions for audit?
2. **Multi-User Terminal**: Can multiple admins share a terminal session?
3. **Dashboard Caching**: Should we cache proxied dashboard assets?
4. **Rate Limiting**: What limits on tunnel traffic per sensor?
5. **Offline Sensors**: How long to retain metrics for offline sensors?
