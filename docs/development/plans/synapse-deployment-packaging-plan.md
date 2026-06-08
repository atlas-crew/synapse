# Synapse Deployment Packaging Plan

## Goal

Make Synapse easy to deploy across the paths real operators are likely to choose: Docker/Compose, managed PaaS, static dashboard hosting, managed containers, and Kubernetes through Helm. The packaging work should preserve a clear production story while keeping demo installs approachable.

## Product Shape

Synapse is not a single serverless application. The deployable surface is split across:

- Synapse Fleet API: long-running Node/Express service with REST, WebSocket sensor ingestion, WebSocket dashboard fanout, Prisma/PostgreSQL persistence, optional Redis queues, and optional ClickHouse analytics.
- Synapse Fleet UI: static React/Vite dashboard that points at Fleet REST and WebSocket endpoints.
- Synapse WAF: Rust/Pingora reverse proxy and WAF sensor with proxy, admin, health, and metrics ports.
- Supporting stores: required PostgreSQL, recommended Redis, optional ClickHouse.

## Deployment Tracks

Package and document these deployment tracks as first-class options:

- Docker Compose / VPS: canonical self-hosting baseline and local production-shaped reference.
- Render: managed hosted path aligned with the existing `render.yaml` shape for static UI, Node API, Postgres, Redis/Key Value, migrations, and health checks.
- Fly.io: container-native path for Fleet and WAF images, with regional placement, volumes/secrets, and service port guidance.
- Vercel or static hosting: dashboard-only path that points at an externally hosted Fleet API and WebSocket endpoint.
- Railway: low-friction managed app path for Fleet API plus managed Postgres/Redis.
- Cloud Run: managed-container path for Fleet API with explicit WebSocket/session, timeout, and scaling notes.
- Kubernetes / Helm: production Kubernetes path for operators who want charts, GitOps, and cluster-native networking/secrets.

## Helm Chart Strategy

Ship separate charts plus an umbrella chart:

- `charts/synapse-fleet`: Fleet API, UI/static hosting option, migration job, service, ingress, secrets, config, and optional Redis/ClickHouse integration points.
- `charts/synapse-waf`: WAF proxy sensor deployment, config map or secret-backed `config.yaml`, services for proxy/admin/metrics, telemetry wiring to Fleet, and optional ServiceMonitor.
- `charts/synapse`: umbrella chart that composes Fleet + WAF and can enable development/demo dependencies.

Production defaults should prefer externally managed PostgreSQL and Redis. Bundled dependency charts are acceptable for demo/dev profiles but should not be the production path.

## Hosting Decision Guide

The docs should make the tradeoffs crisp:

- Choose Docker Compose/VPS for simple self-hosting, demos, and environments without Kubernetes.
- Choose Render when the operator wants the fastest managed full-stack deployment and is comfortable with the Blueprint model.
- Choose Fly.io when the operator wants container-native deployment, regional placement, and a good fit for both Fleet and WAF containers.
- Choose Vercel/static hosting only for the dashboard; Fleet API and WebSockets must live elsewhere.
- Choose Railway for quick managed staging or proofs of concept with managed data services.
- Choose Cloud Run for managed containers in Google Cloud, with documented WebSocket reconnect and timeout behavior.
- Choose Helm/Kubernetes for production teams already operating clusters, ingress controllers, secrets managers, and observability stacks.

## Operator Experience

Target Helm install flow:

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

- Admin/metrics service is private by default across every deployment method.
- WAF proxy may be public only when intentionally configured.
- Secrets can be created from values for demo, but production docs prefer provider secret stores or existing secret references.
- Prisma migrations run through an explicit predeploy command, release step, or Job/hook with documented rollback behavior.
- ClickHouse is disabled by default.

## Deliverables

- Deployment decision matrix and provider-specific guides.
- Valid Helm charts with lint/template coverage.
- Example values/config for demo, managed hosted services, and production Kubernetes.
- Documentation for installation, upgrades, secrets, migrations, observability, WebSocket behavior, and cloud load-balancer notes.
- CI that lints, templates, packages, and publishes chart artifacts where applicable.
