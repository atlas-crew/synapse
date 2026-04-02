---
layout: home

hero:
  name: Horizon
  text: Edge Protection Platform
  tagline: Fleet intelligence and WAF engine for collective defense
  actions:
    - theme: brand
      text: Live Demo
      link: https://horizon-demo.nickf4.workers.dev
    - theme: alt
      text: Get Started
      link: /getting-started/

features:
  - title: Synapse WAF Engine
    details: Pure Rust WAF built on Cloudflare Pingora. ~10 μs clean GET latency, 237 production rules, configurable detection and DLP scanning. Deploy standalone or as a fleet sensor.
    link: /architecture/synapse
  - title: Fleet Intelligence
    details: Multi-tenant signal aggregation with cross-tenant campaign correlation via anonymized fingerprints. Horizon acts as the central intelligence hub for distributed Synapse fleets.
    link: /architecture/horizon
  - title: Real-Time Telemetry
    details: WebSocket signal pipeline with dual-write to PostgreSQL and ClickHouse. Live threat feeds, campaign timelines, and geographic visualization for SOC operators.
    link: /architecture/data-flow
  - title: Deployment Flexibility
    details: Docker, Kubernetes, or bare metal. Run Synapse as a standalone WAF or connect it to the full Horizon platform for centralized fleet management.
    link: /deployment/
  - title: Configuration Hot-Reload
    details: ~240 μs atomic config swap with zero dropped requests. Push rule changes from Horizon and watch them propagate across the fleet in real time.
    link: /configuration/synapse
  - title: Comprehensive Detection
    details: SQLi, XSS, path traversal, command injection, DLP, bot detection, behavioral profiling, and session tracking — all in a single binary with sub-millisecond latency.
    link: /reference/synapse-features
---
