---
title: Getting Started
---

# Getting Started

Horizon is an edge protection platform that pairs a central intelligence hub with distributed WAF sensors. This section covers the platform architecture, system requirements, and how to get a development environment running.

::: tip Try it now
Explore the Horizon dashboard with synthetic data — no install required: [**Live Demo**](https://horizon-demo.nickf4.workers.dev)
:::

## What is Horizon?

Horizon is the **fleet intelligence hub** — a web application that aggregates, correlates, and visualizes security signals from one or more Synapse WAF engines. It provides:

- **Multi-tenant management** — configure sites, rules, and thresholds per tenant
- **Signal aggregation** — collect and normalize WAF events from the fleet
- **Cross-tenant correlation** — detect campaigns spanning multiple tenants using anonymized fingerprints
- **Real-time dashboards** — live threat feeds, geographic maps, campaign timelines

Horizon is built with Node.js/Express, React 19, PostgreSQL, and optionally ClickHouse for high-volume analytics.

## What is Synapse?

Synapse is a **standalone WAF engine** built in pure Rust on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It operates as a reverse proxy that inspects, scores, and filters HTTP traffic before forwarding it to your upstream servers.

Synapse is fully capable on its own — you do not need Horizon to run it. When connected to Horizon, Synapse reports telemetry and receives configuration updates, but it can also run independently with a local YAML configuration file.

::: info Standalone vs. Fleet Mode
**Standalone** — Synapse reads its configuration from a local YAML file and logs events locally. No Horizon dependency.

**Fleet mode** — Synapse connects to a Horizon instance over WebSocket, receives rule updates, and reports signals back for centralized analysis.
:::

## Platform Components

| Component | Technology | Default Port | Role |
| --- | --- | --- | --- |
| **Horizon API** | Node.js / Express | `3100` | REST API, WebSocket signal pipeline, fleet management |
| **Horizon UI** | React 19 / Vite | `5180` | Admin dashboard and configuration UI |
| **Synapse** | Rust / Pingora | `6190` (proxy) `6191` (admin) | WAF engine, reverse proxy, signal emitter |
| **PostgreSQL** | 15+ | `5432` | Primary data store — tenants, rules, signals |
| **ClickHouse** | 23.8+ | `8123` / `9000` | High-volume signal analytics (optional) |
| **Redis** | 7+ | `6379` | Caching and fleet pub/sub (optional) |

## Which Deployment Model?

| Need | Model | What You Get |
| --- | --- | --- |
| Fast, lightweight WAF | **Synapse standalone** | ~10 μs detection, YAML config, local logging |
| Centralized fleet management | **Full platform** | Rule distribution, cross-tenant correlation, dashboards |
| Start small, grow later | **Standalone → fleet** | Begin with one Synapse instance, add Horizon when ready |

::: tip Migration path
Many teams start with Synapse standalone and add Horizon later. The migration is straightforward — point Synapse at a Horizon endpoint and it begins reporting signals automatically.
:::

## Next Steps

- [Installation](./installation) — install via Docker, npm, or from source
- [System Requirements](./requirements) — hardware and software prerequisites
- [Quick Start](./quickstart) — verify your installation and send test traffic
