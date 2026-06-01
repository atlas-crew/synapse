---
id: doc-1
title: Kubernetes and Helm packaging plan
type: specification
created_date: '2026-06-01 18:53'
updated_date: '2026-06-01 18:53'
tags:
  - helm
  - kubernetes
  - deployment
  - synapse
---
# Kubernetes and Helm Packaging Plan

## Goal

Make Synapse deployable for Kubernetes operators through supported Helm charts while preserving the lighter-weight hosting paths that already exist for Docker, Render, Fly.io, and static UI hosting. The chart should package the production control plane cleanly, make demo installs easy, and keep production database ownership explicit.

## Product Shape

Synapse is not a single serverless application. The deployable surface is split across:

- Synapse Fleet API: long-running Node/Express service with REST, WebSocket sensor ingestion, WebSocket dashboard fanout, Prisma/PostgreSQL persistence, optional Redis queues, and optional ClickHouse analytics.
- Synapse Fleet UI: static React/Vite dashboard that points at Fleet REST and WebSocket endpoints.
- Synapse WAF: Rust/Pingora reverse proxy and WAF sensor with proxy, admin, health, and metrics ports.
- Supporting stores: required PostgreSQL, recommended Redis, optional ClickHouse.

## Chart Strategy

Ship separate charts plus an umbrella chart:

- `charts/synapse-fleet`: Fleet API, UI/static hosting option, migration job, service, ingress, secrets, config, and optional Redis/ClickHouse integration points.
- `charts/synapse-waf`: WAF proxy sensor deployment, config map or secret-backed `config.yaml`, services for proxy/admin/metrics, telemetry wiring to Fleet, and optional ServiceMonitor.
- `charts/synapse`: umbrella chart that composes Fleet + WAF and can enable development/demo dependencies.

Production defaults should prefer externally managed PostgreSQL and Redis. Bundled dependency charts are acceptable for demo/dev profiles but should not be the production path.

## Operator Experience

Target install flow:

```bash
helm repo add atlascrew https://charts.atlascrew.dev
helm install synapse atlascrew/synapse \
  --set fleet.database.url="$DATABASE_URL" \
  --set fleet.redis.url="$REDIS_URL" \
  --set waf.telemetry.apiKey="$SYNAPSE_API_KEY"
```

The chart should also support an OCI registry path such as `oci://ghcr.io/atlas-crew/charts/synapse` if that becomes the preferred release channel.

## Required Values Surface

- image repository, tag, pull policy for Fleet and WAF
- Fleet environment: `DATABASE_URL`, `REDIS_URL`, `CLICKHOUSE_ENABLED`, `CORS_ORIGINS`, `JWT_SECRET`, `TELEMETRY_JWT_SECRET`, `CONFIG_ENCRYPTION_KEY`, `METRICS_AUTH_TOKEN`
- WebSocket paths and public URL values for UI builds or runtime config
- ingress hosts, TLS, annotations, and class names
- WAF proxy/admin ports, upstream target config, telemetry endpoint/api key, admin key, resource limits
- pod security context, service account, node selectors, tolerations, affinity, pod disruption budgets
- metrics/service monitor toggles

## Safety Defaults

- Admin/metrics service is ClusterIP by default.
- WAF proxy may be LoadBalancer/Ingress only when explicitly configured.
- Secrets can be created from values for demo, but production docs prefer existing secret references.
- Prisma migrations run through an explicit Job/hook with documented rollback behavior.
- ClickHouse is disabled by default.

## Deliverables

- Valid Helm charts with lint/template coverage.
- Example values for demo, Render-adjacent managed services, and production Kubernetes.
- Documentation for installation, upgrades, secrets, migrations, observability, and cloud load-balancer notes.
- CI that lints, templates, packages, and publishes chart artifacts.
