---
title: Hosting Options
---

# Hosting Options

Use this guide to choose where each Synapse component should run before you
follow a provider-specific deployment guide.

Synapse has three deployment surfaces:

- **Synapse Fleet API**: a long-running Node.js service with REST endpoints,
  sensor WebSockets, dashboard WebSockets, PostgreSQL, optional Redis, and
  optional ClickHouse.
- **Synapse Fleet UI**: a static React/Vite dashboard that needs the public
  Fleet API URL and dashboard WebSocket URL.
- **Synapse WAF**: a Rust/Pingora reverse proxy with a public proxy port and a
  private admin/metrics port.

## Decision Matrix

| Deployment target | Fleet API | Fleet UI | WAF proxy | Data services | Best fit |
| --- | --- | --- | --- | --- | --- |
| Docker Compose / VPS | Yes | Yes | Yes | Local containers or managed services | Portable self-hosting, demos, production-shaped single-host installs |
| Render | Yes | Yes | Not the first choice | Render Postgres and Render Key Value | Fast managed Fleet deployment from `render.yaml` |
| Fly.io | Yes | Static or separate app | Yes | Fly Postgres, Upstash, or external services | Container-native regional deployments |
| Vercel / static hosting | No | Yes | No | External only | Dashboard-only hosting with Fleet API elsewhere |
| Railway | Yes | Yes | Not the first choice | Railway Postgres and Redis-compatible services | Low-friction staging and proofs of concept |
| Cloud Run | Yes, with WebSocket timeout planning | Static or separate service | Not the first choice | Cloud SQL, Memorystore, or external services | Managed containers in Google Cloud |
| Kubernetes / Helm | Yes | Yes | Yes | External or cluster-managed | Production clusters, GitOps, ingress, and platform teams |

::: warning Vercel is dashboard-only
Vercel Functions do not act as a WebSocket server. Host the Synapse Fleet API
on Render, Fly.io, Cloud Run, Kubernetes, or a VM, then point the static
dashboard at that API and WebSocket endpoint.
:::

## Recommended Paths

### Start with Docker Compose

Use Docker Compose when you want a local or VM-based baseline that exercises all
runtime surfaces. Compose is also the easiest way to see which ports, secrets,
and stores the other deployment methods need to provide.

Choose Compose when:

- you are evaluating Synapse on a single host
- you want a production-shaped staging environment
- you need to run Fleet and WAF together without Kubernetes
- you want full control over database backups and network policy

Move to managed hosting or Kubernetes when you need managed databases, regional
placement, autoscaling, or a platform-owned release process.

### Use Render for the fastest managed Fleet path

The repository includes `render.yaml`, which maps cleanly to a Render Blueprint:

- static site for the Synapse Fleet UI
- Node web service for the Fleet API
- Render Postgres for `DATABASE_URL`
- Render Key Value for `REDIS_URL`
- a predeploy command for Prisma migrations

Render is a good default for hosted Fleet. Keep Synapse WAF on Fly.io, a VM, or
Kubernetes unless you have validated a Render-specific proxy topology.

### Use Fly.io for containers and regional placement

Fly.io is a good fit when you want to deploy the existing Dockerfiles or
published images without adopting Kubernetes. It can host Fleet and WAF as
separate apps, with private networking between them when they share an
organization and region strategy.

Use separate apps for:

- `synapse-fleet`: port `3100`, health path `/health`
- `synapse-waf`: proxy port `6190`, admin/metrics port `6191`

Keep the WAF admin surface private. Expose only the proxy listener unless you
have a trusted network path for admin and metrics.

### Use Vercel or static hosting for the dashboard only

The dashboard is static after build, so Vercel, Render Static Sites, GitHub
Pages, Netlify, or an object-storage CDN can host it. Configure it with:

- `VITE_API_URL`: public HTTPS URL for the Fleet API
- `VITE_WS_URL`: public WSS URL for `/ws/dashboard`
- `VITE_HORIZON_API_KEY`: dashboard API key, if the deployment uses static key
  injection

The `VITE_HORIZON_API_KEY` name is still supported during the Synapse Fleet
rename window.

The Fleet API must still run on a long-lived service that supports REST and
WebSockets.

### Use Railway or Cloud Run for managed-container experiments

Railway is useful for quick Fleet API deployments because it can provide
PostgreSQL and inject `DATABASE_URL`. Treat it as a convenient staging or proof
of concept path until you have production backup, network, and secret handling
documented for your account.

Cloud Run can run WebSocket services, but WebSocket streams are still bounded by
the service request timeout. Configure clients to reconnect, plan for best-effort
session affinity, and use Redis or another shared store if multiple instances
must broadcast the same dashboard state.

### Use Helm for Kubernetes teams

Use Helm when you already operate Kubernetes and want cluster-native deployment,
ingress, secrets, service accounts, network policy, and observability.

The planned chart structure is:

- `charts/synapse-fleet`: Fleet API, UI option, migrations, secrets, service,
  ingress, and optional Redis/ClickHouse integration points
- `charts/synapse-waf`: WAF deployment, config, proxy/admin services, telemetry,
  and metrics
- `charts/synapse`: umbrella chart for full-stack installs

## Docker Compose Baseline

The [Docker guide](./docker) is the canonical Compose baseline. It runs Synapse
Fleet, Synapse WAF, PostgreSQL, Redis, and optional ClickHouse on one host.

Use that baseline for demos, staging, and operator evaluation. For production,
provide strong secrets through `.env` or your host secret manager, pin image
tags, and move PostgreSQL and Redis to managed or backed-up services when
possible.

## Network and Secret Defaults

Use these defaults across all deployment methods:

- expose the Fleet API over HTTPS/WSS
- expose the WAF proxy only where it should receive protected application
  traffic
- keep the WAF admin and metrics port private or bound to localhost
- do not expose PostgreSQL, Redis, or ClickHouse to the public internet
- use provider secret stores or existing Kubernetes secrets for production
- run Prisma migrations as an explicit deploy step before new Fleet API
  instances receive traffic
- pin image tags in production instead of using `latest`

## Verification Checklist

After deploying any target, verify:

```sh
curl -f https://fleet.example.com/health
curl -f http://synapse-admin.internal:6191/status
```

Then confirm:

- the dashboard loads and reaches `VITE_API_URL`
- the dashboard WebSocket connects to `/ws/dashboard`
- at least one WAF sensor can report telemetry to Fleet
- PostgreSQL has persistent storage and backups
- Redis is configured before scaling Fleet API past one instance
- ClickHouse is disabled unless historical analytics are intentionally enabled

## Provider References

- [Render Blueprint YAML reference](https://render.com/docs/blueprint-spec)
- [Fly.io app configuration](https://www.fly.io/docs/reference/configuration/)
- [Vercel limits](https://vercel.com/docs/limits/overview)
- [Railway PostgreSQL](https://docs.railway.com/databases/postgresql/)
- [Cloud Run WebSockets](https://docs.cloud.google.com/run/docs/triggering/websockets)
