# Signal Horizon: Fleet Management & Aggregation Spec

## Overview

Signal Horizon is the **central command plane** for Atlas Crew sensor fleets. It combines:

1. **Aggregated Metrics** - Fleet-wide view of what Signal Array shows per-sensor
2. **Drill-Down** - Click any sensor → see its full dashboard (like Netdata)
3. **Central Management** - Push configs, updates, rules from one place
4. **Threat Intelligence** - Campaign correlation, hunting, War Room (already specced)

Think: **Netdata Cloud meets CrowdStrike Falcon**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SIGNAL HORIZON HUB                                │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Aggregator  │  │ Config      │  │ Threat      │  │ Fleet       │        │
│  │ Service     │  │ Manager     │  │ Correlator  │  │ Commander   │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │               │
│         └────────────────┴────────────────┴────────────────┘               │
│                                    │                                        │
│                            ┌───────┴───────┐                               │
│                            │   WebSocket   │                               │
│                            │   Gateway     │                               │
│                            └───────┬───────┘                               │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
            ▼                        ▼                        ▼
     ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
     │  Sensor 1   │          │  Sensor 2   │          │  Sensor N   │
     │  (Synapse)  │          │  (Synapse)  │          │  (Synapse)  │
     └─────────────┘          └─────────────┘          └─────────────┘
```

### Data Flow

**Inbound (Sensors → Hub):**
- Health metrics (CPU, mem, disk, network)
- Request metrics (RPS, latency, errors)
- Threat signals (blocks, challenges, anomalies)
- Config state (current config hash, version)

**Outbound (Hub → Sensors):**
- Config updates
- Rule pushes
- Blocklist updates
- Commands (restart, update, diagnostics)

---

## Aggregated Views

### 1. Fleet Overview (Aggregated Signal Array)

What Signal Array shows for ONE sensor → Signal Horizon shows for ALL.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Fleet Overview                                    [Export] [+ Add Sensor]  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │      24      │  │      21      │  │       2      │  │       1      │    │
│  │   SENSORS    │  │    ONLINE    │  │   WARNING    │  │   OFFLINE    │    │
│  │              │  │  ✓ Healthy   │  │  ⚠ Attention │  │  ✗ Down      │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    2.4M      │  │    18ms      │  │   0.12%      │  │    847K      │    │
│  │  TOTAL RPS   │  │  AVG LATENCY │  │  ERROR RATE  │  │   BLOCKED    │    │
│  │  ↑ 12%       │  │  ↓ 8%        │  │  — stable    │  │  ↑ 15%       │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  Fleet Traffic (24h)                              [1H] [6H] [24H] [7D]     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │     ▄▄▄                                                             │   │
│  │    ████▄                                    ▄▄▄▄▄                   │   │
│  │   ██████▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█████████▄▄▄▄             │   │
│  │  ████████████████████████████████████████████████████████          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐  │
│  │  Resource Utilization           │  │  Traffic by Region              │  │
│  │                                 │  │                                 │  │
│  │  CPU    ████████░░░░  32%      │  │  🇺🇸 US East    847K   35.2%    │  │
│  │  Memory ██████████░░  58%      │  │  🇺🇸 US West    521K   21.7%    │  │
│  │  Disk   █████░░░░░░░  41%      │  │  🇪🇺 EU West    412K   17.1%    │  │
│  │  Network ████████░░░  67%      │  │  🇪🇺 EU Central 298K   12.4%    │  │
│  │                                 │  │  🌏 Asia Pac   327K   13.6%    │  │
│  └─────────────────────────────────┘  └─────────────────────────────────┘  │
│                                                                             │
│  Sensor Fleet                                          [Search] [Filter]   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ SENSOR              STATUS    CPU   MEM   RPS      LATENCY  REGION  │   │
│  │─────────────────────────────────────────────────────────────────────│   │
│  │ sensor-prod-us-e-01 ● Online  23%   45%   12.4K    18ms    us-east  │   │
│  │ sensor-prod-us-e-02 ● Online  31%   52%   8.7K     21ms    us-east  │   │
│  │ sensor-prod-eu-01   ⚠ Warning 67%   87%   15.2K    45ms    eu-west  │   │
│  │ sensor-prod-us-w-03 ✗ Offline --    --    --       --      us-west  │   │
│  │ sensor-prod-asia-01 ● Online  45%   61%   9.3K     32ms    ap-south │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Aggregated Health Metrics

Fleet-wide health with drill-down capability.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Fleet Health                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────┐  Health Components                         │
│  │                            │                                            │
│  │           94               │  CPU Utilization                     32%   │
│  │                            │  ████████░░░░░░░░░░░░  Avg across 24       │
│  │     Fleet Health Score     │                                            │
│  │     Excellent - All        │  Memory Usage                        58%   │
│  │     systems operational    │  ██████████████░░░░░░  2 sensors > 80%    │
│  │                            │                                            │
│  └────────────────────────────┘  Disk Usage                          41%   │
│                                   ██████████░░░░░░░░░░  All healthy        │
│                                                                            │
│                                   Connectivity                       96%   │
│                                   ███████████████████░  1 sensor offline  │
│                                                                             │
│  Fleet Performance                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  P50 Latency      P95 Latency      P99 Latency      Error Rate     │   │
│  │      12ms             34ms             89ms           0.12%        │   │
│  │    ↓ 5% vs 24h      ↓ 3% vs 24h     ↑ 2% vs 24h    — stable       │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Sensors Requiring Attention                                    [View All] │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ ⚠ sensor-prod-eu-01      High memory (87%)      45 min ago         │   │
│  │ ✗ sensor-prod-us-west-03  Offline               23 min ago         │   │
│  │ ⚠ sensor-prod-asia-02     Disk space (82%)      1 hr ago           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3. Aggregated Threat Activity

Fleet-wide threat view (combines with existing Signal Horizon threat intel).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Fleet Threat Activity                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    2,847     │  │     127      │  │     534      │  │      12      │    │
│  │ TOTAL (24H)  │  │   CRITICAL   │  │     HIGH     │  │  CAMPAIGNS   │    │
│  │  ↑ 18%       │  │   ↑ 23 new   │  │   ↓ 12%      │  │   3 active   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  Attack Distribution                     Threats by Sensor                  │
│  ┌─────────────────────────────┐        ┌─────────────────────────────┐    │
│  │                             │        │                             │    │
│  │  SQL Injection    ████ 28%  │        │ us-east-01  ████████  847   │    │
│  │  Bot Traffic      ███░ 24%  │        │ us-east-02  ██████    521   │    │
│  │  XSS              ███░ 18%  │        │ eu-west-01  █████     412   │    │
│  │  Brute Force      ██░░ 15%  │        │ asia-01     ████      327   │    │
│  │  Scraping         █░░░ 10%  │        │ us-west-02  ███       298   │    │
│  │  Other            █░░░  5%  │        │ Other       ███       442   │    │
│  │                             │        │                             │    │
│  └─────────────────────────────┘        └─────────────────────────────┘    │
│                                                                             │
│  Fleet Threat Heatmap (7 days)                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │     Mon   Tue   Wed   Thu   Fri   Sat   Sun                         │   │
│  │ 00  ▓▓▓   ▓▓░   ▓░░   ▓▓░   ▓▓▓   ░░░   ░░░                        │   │
│  │ 06  ▓░░   ▓▓░   ▓▓▓   ▓▓▓   ▓▓░   ░░░   ░░░                        │   │
│  │ 12  ▓▓▓   ▓▓▓   ▓▓▓   ▓▓▓   ▓▓▓   ▓░░   ░░░                        │   │
│  │ 18  ▓▓░   ▓▓▓   ▓▓░   ▓▓▓   ▓▓▓   ▓▓░   ▓░░                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Drill-Down: Sensor Detail

Click any sensor → See full Signal Array dashboard, but from Signal Horizon.

**URL Pattern:** `/fleet/sensors/{sensor_id}`

This is essentially the same views from Signal Array (pages 12-22 of the PDF), but:
- Accessed from central console
- Can take remote actions
- Compare to fleet averages

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Signal Horizon > Fleet > sensor-prod-us-east-01                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  sensor-prod-us-east-01                    ● Online                         │
│  snsr_8f2k4m9x | us-east-1 | v4.2.1                                        │
│                                                                             │
│  [Overview] [Performance] [Network] [Processes] [Logs] [Configuration]     │
│                                                                             │
│  ... (Same content as Signal Array sensor detail, pages 14-19) ...         │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  REMOTE ACTIONS                                                     │   │
│  │                                                                     │   │
│  │  [↻ Restart Services]  [⚡ Run Diagnostics]  [⬆ Push Update]       │   │
│  │  [📋 Push Config]      [🔑 Rotate Keys]      [📦 Collect Logs]     │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Central Management

### 1. Configuration Manager

Push configs to sensors from central console.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Configuration Manager                          [View History] [Templates] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │      24      │  │      21      │  │       3      │  │       0      │    │
│  │    SENSORS   │  │   IN SYNC    │  │  OUT OF SYNC │  │   PENDING    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  Configuration Templates                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │   │
│  │  │ 🏭 Production   │  │ 🧪 Staging      │  │ 🔬 Development  │     │   │
│  │  │ 18 sensors      │  │ 4 sensors       │  │ 2 sensors       │     │   │
│  │  │ Last sync: 2h   │  │ Last sync: 1d   │  │ Last sync: 3d   │     │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘     │   │
│  │                                                                     │   │
│  │                              [+ Create Template]                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Recent Configuration Changes                                   [View All] │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2h ago   worker_connections: 4096 → 10000    18 sensors   [Revert] │   │
│  │ 1d ago   net.core.somaxconn: 128 → 65535     18 sensors   [Revert] │   │
│  │ 3d ago   Auto-Updates: Disabled → Enabled    24 sensors   [Revert] │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Push Configuration                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  Select Sensors:  ○ All  ○ By Template  ● Select                   │   │
│  │                                                                     │   │
│  │  ☑ sensor-prod-us-east-01    ☑ sensor-prod-us-east-02              │   │
│  │  ☑ sensor-prod-eu-01         ☐ sensor-prod-us-west-03 (offline)    │   │
│  │  ☑ sensor-prod-asia-01                                              │   │
│  │                                                                     │   │
│  │  Configuration:   [General ▼]                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │ worker_connections = 10000                                  │   │   │
│  │  │ keepalive_timeout = 75                                      │   │   │
│  │  │ client_body_buffer_size = 16k                               │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  │  [Validate]  [Preview Diff]              [Push to 5 Sensors]       │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Rule Distribution

Push rules to fleet from central location.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Rule Distribution                               [Import] [+ Create Rule]  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Fleet Rules                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  RULE                         STATUS    SENSORS   TRIGGERS  SYNC   │   │
│  │──────────────────────────────────────────────────────────────────── │   │
│  │  SQL Injection Protection     ● Active    24/24    3,421    ✓      │   │
│  │  XSS Attack Prevention        ● Active    24/24    2,187    ✓      │   │
│  │  Bot Detection                ● Active    24/24    8,932    ✓      │   │
│  │  Credential Stuffing          ● Active    21/24    4,521    ⚠ 3    │   │
│  │  Geo-Blocking                 ● Active    18/24   12,432    ⚠ 6    │   │
│  │  Custom: Block TOR            ○ Staged     0/24        0    —      │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Push Rules                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  Select Rules:     ☑ Credential Stuffing  ☑ Custom: Block TOR      │   │
│  │                                                                     │   │
│  │  Target Sensors:   ○ All Online  ○ Out of Sync Only  ● Select      │   │
│  │                    ☑ us-east-01  ☑ us-east-02  ☑ eu-west-01        │   │
│  │                                                                     │   │
│  │  Rollout Strategy: ○ Immediate  ● Canary (10% → 50% → 100%)        │   │
│  │                    ○ Scheduled: [Dec 22, 2024 02:00 UTC    ]        │   │
│  │                                                                     │   │
│  │                              [Preview]  [Push Rules to 3 Sensors]   │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3. Fleet Updates

Central update management (like page 22 but fleet-wide).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Fleet Updates                              [Update History] [Settings]    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  🎉 New Version Available: v4.2.1                                  │    │
│  │  Released Dec 5, 2024 - Security patch + performance improvements  │    │
│  │                                                                    │    │
│  │  [Release Notes]                          [Update All Sensors]     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │      21      │  │       3      │  │       2      │  │       0      │    │
│  │  UP TO DATE  │  │  AVAILABLE   │  │  SCHEDULED   │  │    FAILED    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  Version Distribution                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  v4.2.1 (latest)  █████████████████████████████████████████  21    │   │
│  │  v4.2.0           ██████                                       3    │   │
│  │  v4.1.8           ██                                           1    │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Bulk Update                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  Select Sensors:                                                    │   │
│  │  ☑ sensor-prod-eu-01      v4.2.0 → v4.2.1                          │   │
│  │  ☑ sensor-prod-asia-02    v4.2.0 → v4.2.1                          │   │
│  │  ☑ sensor-staging-01      v4.2.0 → v4.2.1                          │   │
│  │                                                                     │   │
│  │  Strategy:  ○ Immediate  ● Rolling (one at a time)                 │   │
│  │             ○ Blue/Green  ○ Scheduled                              │   │
│  │                                                                     │   │
│  │  [✓ Auto-rollback on failure]                                      │   │
│  │                                                                     │   │
│  │                              [Preview]  [Start Update for 3]        │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4. Blocklist Management

Fleet-wide blocklist with sync status.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Fleet Blocklist                                  [Import] [+ Add Entry]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    1,247     │  │     892      │  │     312      │  │      43      │    │
│  │  TOTAL IPS   │  │ FINGERPRINTS │  │     ASNS     │  │   PENDING    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
│  [All] [IPs] [Fingerprints] [ASNs] [Pending Sync]                          │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ TYPE    ENTRY               REASON           SYNCED   ADDED         │   │
│  │──────────────────────────────────────────────────────────────────── │   │
│  │ IP      185.220.101.0/24    TOR exit nodes   24/24    2h ago        │   │
│  │ FP      python-requests/*   Bot traffic      24/24    1d ago        │   │
│  │ ASN     AS12345             Bulletproof      21/24    3d ago   ⚠    │   │
│  │ IP      192.241.128.0/20    Campaign #4421   24/24    5d ago        │   │
│  │ FP      curl/7.*            Scanner          18/24    1w ago   ⚠    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Quick Block                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  Type: [IP ▼]  Entry: [                    ]  Reason: [          ] │   │
│  │                                                                     │   │
│  │  Push to:  ● All sensors  ○ Production only  ○ Select              │   │
│  │                                                                     │   │
│  │                                         [Block Fleet-Wide]          │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Model

### Sensor Registration

```typescript
interface Sensor {
  id: string;                    // snsr_8f2k4m9x
  name: string;                  // sensor-prod-us-east-01
  tenantId: string;
  
  // Connection
  status: 'online' | 'warning' | 'offline';
  lastHeartbeat: DateTime;
  publicIp: string;
  privateIp: string;
  
  // Identity
  version: string;               // v4.2.1
  configHash: string;            // SHA256 of current config
  rulesHash: string;             // SHA256 of current rules
  blocklistHash: string;         // SHA256 of current blocklist
  
  // Metadata
  region: string;
  environment: 'production' | 'staging' | 'development';
  tags: Record<string, string>;
  
  // Capabilities
  capabilities: string[];        // ['rules', 'blocklist', 'config', 'diagnostics']
  
  createdAt: DateTime;
  updatedAt: DateTime;
}
```

### Aggregated Metrics

```typescript
interface FleetMetrics {
  timestamp: DateTime;
  
  // Sensor status
  totalSensors: number;
  onlineSensors: number;
  warningSensors: number;
  offlineSensors: number;
  
  // Traffic
  totalRps: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  errorRate: number;
  
  // Resources (averages across fleet)
  avgCpuPercent: number;
  avgMemoryPercent: number;
  avgDiskPercent: number;
  
  // Threats
  totalThreats24h: number;
  criticalThreats: number;
  highThreats: number;
  blockedRequests: number;
  activeCampaigns: number;
  
  // By region
  metricsByRegion: Record<string, RegionMetrics>;
}

interface RegionMetrics {
  region: string;
  sensorCount: number;
  totalRps: number;
  avgLatencyMs: number;
  threatCount: number;
}
```

### Config Sync State

```typescript
interface ConfigSyncState {
  sensorId: string;
  
  // Expected state (from hub)
  expectedConfigHash: string;
  expectedRulesHash: string;
  expectedBlocklistHash: string;
  
  // Actual state (reported by sensor)
  actualConfigHash: string;
  actualRulesHash: string;
  actualBlocklistHash: string;
  
  // Sync status
  configInSync: boolean;
  rulesInSync: boolean;
  blocklistInSync: boolean;
  
  lastSyncAttempt: DateTime;
  lastSyncSuccess: DateTime;
  syncErrors: string[];
}
```

---

## Sensor Protocol

### Heartbeat (Sensor → Hub)

Every 30 seconds:

```typescript
interface SensorHeartbeat {
  sensorId: string;
  timestamp: DateTime;
  
  // Health
  status: 'healthy' | 'degraded' | 'unhealthy';
  cpu: number;
  memory: number;
  disk: number;
  
  // Traffic
  requestsLastMinute: number;
  avgLatencyMs: number;
  errorRate: number;
  
  // Threats
  threatsLastMinute: number;
  blocksLastMinute: number;
  
  // Sync state
  configHash: string;
  rulesHash: string;
  blocklistHash: string;
  version: string;
}
```

### Commands (Hub → Sensor)

```typescript
type SensorCommand = 
  | { type: 'push_config'; config: SensorConfig }
  | { type: 'push_rules'; rules: Rule[] }
  | { type: 'push_blocklist'; entries: BlocklistEntry[] }
  | { type: 'update'; version: string; url: string }
  | { type: 'restart'; services?: string[] }
  | { type: 'collect_diagnostics'; types: string[] }
  | { type: 'rotate_keys' };

interface CommandResponse {
  commandId: string;
  sensorId: string;
  status: 'success' | 'failed' | 'pending';
  result?: any;
  error?: string;
  completedAt?: DateTime;
}
```

### WebSocket Protocol

```typescript
// Hub → Sensor
interface HubMessage {
  type: 'command' | 'config_update' | 'rules_update' | 'blocklist_update';
  payload: any;
  commandId?: string;
}

// Sensor → Hub
interface SensorMessage {
  type: 'heartbeat' | 'metrics' | 'threat_signal' | 'command_response' | 'log';
  payload: any;
  commandId?: string;
}
```

---

## Aggregation Service

### Real-Time Aggregation

```typescript
class FleetAggregator {
  private sensorMetrics: Map<string, SensorMetrics> = new Map();
  
  // Update from heartbeat
  updateSensorMetrics(sensorId: string, heartbeat: SensorHeartbeat) {
    this.sensorMetrics.set(sensorId, {
      ...heartbeat,
      updatedAt: Date.now(),
    });
  }
  
  // Compute fleet-wide metrics
  getFleetMetrics(): FleetMetrics {
    const sensors = Array.from(this.sensorMetrics.values());
    const online = sensors.filter(s => this.isOnline(s));
    
    return {
      timestamp: new Date(),
      
      // Status
      totalSensors: sensors.length,
      onlineSensors: online.length,
      warningSensors: sensors.filter(s => s.status === 'degraded').length,
      offlineSensors: sensors.filter(s => !this.isOnline(s)).length,
      
      // Traffic (sum for RPS, weighted avg for latency)
      totalRps: sum(online.map(s => s.requestsLastMinute / 60)),
      avgLatencyMs: weightedAverage(
        online.map(s => s.avgLatencyMs),
        online.map(s => s.requestsLastMinute)
      ),
      
      // Resources (simple average)
      avgCpuPercent: average(online.map(s => s.cpu)),
      avgMemoryPercent: average(online.map(s => s.memory)),
      avgDiskPercent: average(online.map(s => s.disk)),
      
      // Threats (sum)
      totalThreats24h: sum(online.map(s => s.threats24h)),
      blockedRequests: sum(online.map(s => s.blocked24h)),
      
      // ... etc
    };
  }
  
  private isOnline(sensor: SensorMetrics): boolean {
    return Date.now() - sensor.updatedAt < 60_000; // 60s timeout
  }
}
```

### Historical Aggregation

Store aggregated metrics for trends:

```sql
-- ClickHouse
CREATE TABLE fleet_metrics_hourly (
    timestamp DateTime,
    tenant_id String,
    
    -- Sensor counts
    total_sensors UInt32,
    online_sensors UInt32,
    
    -- Traffic
    total_requests UInt64,
    avg_latency_ms Float32,
    p99_latency_ms Float32,
    error_rate Float32,
    
    -- Resources
    avg_cpu Float32,
    avg_memory Float32,
    
    -- Threats
    total_threats UInt64,
    blocked_requests UInt64,
    
    -- By region (nested)
    region_metrics Nested(
        region String,
        requests UInt64,
        latency Float32
    )
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp);
```

---

## Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| **1** | Sensor heartbeat protocol + fleet overview | 1 week |
| **2** | Aggregated metrics + health dashboard | 1 week |
| **3** | Sensor drill-down (embed Signal Array views) | 1 week |
| **4** | Config push + sync status | 1 week |
| **5** | Rule distribution | 1 week |
| **6** | Fleet updates | 1 week |
| **7** | Blocklist management | 3 days |
| **8** | Historical trends + alerts | 1 week |

**Total: ~7-8 weeks**

### Phase 1 Deliverables
- [ ] Sensor WebSocket connection to hub
- [ ] Heartbeat message handling
- [ ] Basic fleet overview page
- [ ] Sensor status (online/offline)

### Phase 2 Deliverables
- [ ] Real-time aggregation service
- [ ] Fleet metrics API
- [ ] Fleet Overview dashboard
- [ ] Health Metrics dashboard

### Phase 3 Deliverables
- [ ] Sensor detail pages
- [ ] Embed Signal Array views
- [ ] Navigation between fleet and sensor
- [ ] Comparison to fleet averages

### Phase 4 Deliverables
- [ ] Config templates
- [ ] Config push API
- [ ] Sync status tracking
- [ ] Config diff/preview

### Phase 5 Deliverables
- [ ] Rule sync protocol
- [ ] Bulk rule push
- [ ] Canary/rolling rollout
- [ ] Rule trigger aggregation

### Phase 6 Deliverables  
- [ ] Version tracking
- [ ] Update push protocol
- [ ] Rolling update orchestration
- [ ] Auto-rollback

### Phase 7 Deliverables
- [ ] Blocklist sync
- [ ] Fleet-wide block actions
- [ ] Sync status per entry

### Phase 8 Deliverables
- [ ] Historical aggregation (ClickHouse)
- [ ] Trend charts
- [ ] Fleet alerts
- [ ] Scheduled reports

---

## Netdata Comparison

| Feature | Netdata Cloud | Signal Horizon |
|---------|---------------|----------------|
| Aggregate metrics | ✅ | ✅ |
| Drill-down to node | ✅ | ✅ |
| Real-time streaming | ✅ | ✅ |
| Config push | ❌ | ✅ |
| Remote commands | ❌ | ✅ |
| Threat correlation | ❌ | ✅ |
| Rule distribution | ❌ | ✅ |
| Update orchestration | ❌ | ✅ |

Signal Horizon = Netdata Cloud + Fleet Management + Threat Intel

---

## Navigation Structure

```
Signal Horizon
├── Fleet Overview (aggregated Signal Array)
├── Sensors
│   ├── All Sensors (table)
│   └── [sensor-id]
│       ├── Overview
│       ├── Performance
│       ├── Network
│       ├── Processes
│       ├── Logs
│       └── Configuration
├── Threat Intelligence (existing spec)
│   ├── Threat Overview
│   ├── Active Campaigns
│   ├── Threat Hunting
│   ├── Global Intel
│   └── War Room
├── Fleet Management
│   ├── Configuration
│   ├── Rules
│   ├── Updates
│   └── Blocklist
└── Settings
    ├── Sharing Preferences
    ├── Auto-Block Rules
    └── API Access
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Heartbeat latency | < 100ms |
| Config push success rate | > 99% |
| Fleet overview load time | < 1s |
| Sensor drill-down load time | < 500ms |
| Rule sync time (fleet-wide) | < 30s |
| Update rollout time | Configurable per strategy |

---

## What This Enables

| Before | After |
|--------|-------|
| SSH into each sensor | One dashboard |
| Manual config edits | Central push |
| Version drift | Fleet-wide updates |
| Siloed metrics | Aggregate view |
| No fleet visibility | Real-time health |
| Rule inconsistency | Guaranteed sync |
| "Which sensor has that rule?" | Fleet-wide rule status |
