layout: page
title: Signal Horizon
description: Fleet Command & SOC Hub - Real-time sensor management, threat detection, and incident response
permalink: /signal-horizon/

# Signal Horizon

**Signal Horizon** is the central command hub for managing Synapse sensor fleets, monitoring threats in real-time, and coordinating incident response. It provides a unified dashboard for SOC analysts and security engineers to oversee distributed WAF deployments.

## Key Features

<div class="feature-grid">
  <div class="feature-card">
    <h3>Fleet Management</h3>
    <p>Deploy, configure, and monitor Synapse sensors across regions. Push configuration updates, manage firmware, and track health metrics from a single pane of glass.</p>
  </div>
  <div class="feature-card">
    <h3>Real-Time Threat Intelligence</h3>
    <p>Aggregate signals from distributed sensors, detect cross-tenant campaigns, and correlate attack patterns with anomaly detection.</p>
  </div>
  <div class="feature-card">
    <h3>War Room Collaboration</h3>
    <p>Coordinate incident response with real-time activity feeds, automated playbook execution, and @horizon-bot assistance.</p>
  </div>
  <div class="feature-card">
    <h3>API Intelligence</h3>
    <p>Automatic API schema discovery, drift detection, and shadow endpoint identification across your fleet.</p>
  </div>
</div>

---

## Quick Links

### Getting Started

| Document | Description |
|----------|-------------|
| [Setup Guide](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/setup.md) | Local development environment setup |
| [Deployment Guide](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/deployment.md) | Production deployment patterns |
| [Architecture Overview](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/architecture.md) | System design and data flows |

### API Reference

| Document | Description |
|----------|-------------|
| [REST & WebSocket API](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/api.md) | Complete API reference (30KB+) |
| [Fleet Management API](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/fleet-api.md) | Sensor and configuration endpoints |
| [Hunt API](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/hunt-api.md) | Historical threat hunting queries |
| [OpenAPI Spec (JSON)](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/openapi.json) | OpenAPI 3.0 specification |
| [Communication Protocols](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/protocols.md) | WebSocket and sensor protocols |

### Operator Guides

| Guide | Description |
|-------|-------------|
| [Sensor Onboarding](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/sensor-onboarding.md) | Connect sensors to Signal Horizon |
| [Remote Shell Access](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/remote-shell.md) | Secure remote access to sensors |
| [Firmware Updates](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/firmware-updates.md) | Manage sensor firmware lifecycle |
| [Capacity Planning](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/capacity-planning.md) | Plan fleet capacity and scaling |
| [Drift Management](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/drift-management.md) | Detect and resolve config drift |

### Developer Guides

| Guide | Description |
|-------|-------------|
| [API Key Management](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/api-key-management.md) | Create and manage API keys |
| [Threat Investigation API](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/threat-investigation-api.md) | Investigate threats via REST endpoints |
| [Synapse Rules](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/synapse-rules.md) | Write custom detection rules |
| [Rule Authoring Flow](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/rule-authoring-flow.md) | Rule creation workflow |
| [API Intelligence](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/guides/api-intelligence.md) | Schema learning and violation detection |
| [UI Development](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/ui-development.md) | React patterns and state management |

### Feature Documentation

| Feature | Description |
|---------|-------------|
| [Fleet Management](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/features/fleet-management.md) | Sensor fleet operations |
| [Impossible Travel](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/features/impossible-travel.md) | Geographic anomaly detection |
| [War Room](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/features/warroom.md) | Incident collaboration |
| [Payload Forensics](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/payload-forensics.md) | Request/response analysis |
| [War Room Automation](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/tutorials/war-room-automation.md) | Automated playbook execution |

### Architecture Deep Dives

| Document | Description |
|----------|-------------|
| [Signal Array](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/architecture/signal-array.md) | Fleet management architecture (20KB) |
| [Remote Management](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/architecture/remote-management.md) | Remote access system design (32KB) |
| [Database Schema](https://github.com/atlascrew/atlascrew-monorepo/blob/main/apps/signal-horizon/docs/database-schema.md) | PostgreSQL and ClickHouse schemas |

---

## Architecture Overview

Signal Horizon uses a multi-tier architecture for scalability and reliability:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Signal Horizon UI                          │
│           (React + TanStack Query + WebSocket)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┼────────────────────────────────────┐
│                    Signal Horizon API                           │
│         ┌──────────────────┼──────────────────────┐             │
│         │                  │                      │             │
│    REST API          WebSocket Hub         Background Jobs      │
│    (Express)        (Dashboard GW)         (Aggregator)         │
│         │                  │                      │             │
│         └──────────────────┼──────────────────────┘             │
└────────────────────────────┼────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────────┐
         │                   │                       │
    ┌────┴────┐       ┌──────┴──────┐         ┌─────┴─────┐
    │PostgreSQL│       │ ClickHouse │         │  Redis    │
    │ (OLTP)  │       │ (Analytics) │         │ (Cache)   │
    └─────────┘       └─────────────┘         └───────────┘
                             │
┌────────────────────────────┼────────────────────────────────────┐
│                    Sensor Gateway                               │
│              (WebSocket + mTLS + Protocol)                      │
└────────────────────────────┼────────────────────────────────────┘
                             │
    ┌────────────────────────┼────────────────────────────┐
    │           │            │            │               │
┌───┴───┐  ┌───┴───┐   ┌────┴────┐  ┌────┴────┐    ┌────┴────┐
│Sensor │  │Sensor │   │ Sensor  │  │ Sensor  │    │ Sensor  │
│US-E-1 │  │US-W-1 │   │ EU-W-1  │  │ AP-SE-1 │    │  ...    │
└───────┘  └───────┘   └─────────┘  └─────────┘    └─────────┘
```

### Key Components

- **Signal Horizon UI**: React dashboard with real-time updates via WebSocket
- **Signal Horizon API**: Express backend with REST endpoints and WebSocket hub
- **Sensor Gateway**: Handles mTLS sensor connections and command routing
- **Aggregator**: Batches and deduplicates signals for campaign correlation
- **Correlator**: Detects cross-tenant campaigns and threat patterns
- **War Room Service**: Real-time incident collaboration with @horizon-bot

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, TypeScript, TanStack Query, Zustand, Tailwind CSS |
| Backend | Node.js, Express, TypeScript, WebSocket (ws) |
| Database | PostgreSQL (OLTP), ClickHouse (Analytics), Redis (Cache) |
| ORM | Prisma |
| Validation | Zod |
| Sensors | Synapse-Pingora (Rust) |
| Build | Nx, Vite, pnpm |

---

## Related Projects

| Project | Description |
|---------|-------------|
| [Synapse-Pingora](/synapse-pingora/) | Rust-based sensor runtime with WAF, DLP, and tarpit capabilities |
| [Orchestrator](/demo-dashboard/) | Attack simulation and scenario orchestration |
| [TestBed](/demo-targets/) | Vulnerable target infrastructure for testing |
| [Gauntlet](/load-testing/) | High-volume load testing harness |
