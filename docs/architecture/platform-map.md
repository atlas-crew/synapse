# Platform Map

One-page reference for every service, data seam, and maturity state
across the Edge Protection platform plus its two sibling repositories
(`../Apparatus`, `../Chimera`). Written from the operator's point of
view — if you're trying to stand up the demo, join a service to
another service, or figure out whether a given wire is production-ready
or a placeholder, this is the map.

For the user-facing "how do I run the demo" quickstart, see
[site/getting-started/demo-mode.md](../../site/getting-started/demo-mode.md).
For the detailed simulator internals, see
[docs/development/demo-simulator.md](../development/demo-simulator.md).

## High-level topology

```
                           ┌───────────────────┐
                           │   Horizon UI      │
                           │   Vite / React    │
                           │   :5180           │
                           └─────────┬─────────┘
                                     │ WS /ws/dashboard
                                     │ REST /api/v1/…
                                     ▼
  ┌─────────────┐  SSE    ┌─────────────────────┐   Prisma   ┌──────────┐
  │  Apparatus  │────────▶│   Horizon API       │───────────▶│ Postgres │
  │ :8090/:8443 │  /sse   │   Node / tsx        │            │  :5432   │
  │ + protocols │         │   :3100             │            └──────────┘
  └─────┬───────┘         │                     │
        │                 │  - /ws/sensors ────┐│
        │ attack-sim      │  - /ws/dashboard   ││
        │ (target=any)    │  - synapse-direct  ││
        │                 │    adapter (poll)  ││
        ▼                 └──────────┬─────────┘│
  ┌──────────────┐                   │ poll     │ WS push
  │   Chimera    │                   │          │
  │ Flask→ASGI   │               ┌───▼──────────▼───┐
  │  :8880       │               │  Synapse WAF(s)  │
  │  476 routes  │               │  Rust / Pingora  │
  └──────┬───────┘               │  :6190 / :6191   │
         │                       │                  │
         │  (TODO: upstream)     │  - real engine   │
         └───────────────────────│  - simulator     │
            still placeholder    │  - horizon push  │
                                 └──────────────────┘
```

## Services

| Service | Location | Port(s) | Language | Status | Role |
|---|---|---|---|---|---|
| **Horizon API** | `apps/signal-horizon/api` | 3100 | TypeScript / tsx-watch | ✅ production | REST + WebSocket gateways, Prisma ingestion, aggregator pipeline, Apparatus SSE bridge, synapse-direct poller |
| **Horizon UI** | `apps/signal-horizon/ui` | 5180 | React / Vite | ✅ production | Dashboard frontend; consumes `/api/v1/...` and `/ws/dashboard` |
| **Synapse WAF** | `apps/synapse-pingora` | 6190 proxy / 6191 admin | Rust / Pingora | ✅ production | Real WAF engine (248 rules, DLP, correlation, fingerprinting). `--demo` launches the in-process simulator; `--config config.horizon.yaml` wires the HorizonManager push client |
| Synapse WAF #2 | `apps/synapse-pingora` | 6290 / 6291 | Rust | demo-only | `config.horizon.2.yaml`; same binary, different sensor identity |
| Synapse WAF #3 | `apps/synapse-pingora` | 6390 / 6391 | Rust | demo-only | `config.horizon.3.yaml`; same binary, different sensor identity |
| **Apparatus** | `../Apparatus/apps/apparatus` | 8090 HTTP/1, 8443 HTTP/2, 9100 TCP, 50051 gRPC, + protocol servers | TypeScript / Node | ✅ production | Active Defense orchestrator. Drills, attack-sim, red team AI, ghost traffic, scenarios, MQTT/ICAP/SMTP/Syslog sims. Exposes `/sse` for Horizon's bridge |
| **Chimera** | `../Chimera/apps/vuln-api` | 8880 | Python / Flask→ASGI | 🚧 mid-migration | Vulnerable target. 476 routes across 28 blueprints (insurance, ecommerce, healthcare, auth, saas, government, attack_sim, telecom, energy_utilities, …). Mid-migration from Flask/gunicorn to Starlette/uvicorn for throughput |
| **Synapse Client** | `apps/synapse-client` | — | TypeScript | ✅ library | Client-side SDK for integrating Synapse into apps |
| **Synapse API** | `packages/synapse-api` | — | TypeScript | ✅ library | Server-side helpers for Synapse integration |
| PostgreSQL | (system) | 5432 | — | required | Horizon's durable store (Prisma schema) |
| ClickHouse | (system, optional) | 9000 / 8123 | — | optional | Horizon's historical timeseries; not required for local demo |
| Redis | (system, optional) | 6379 | — | optional | Cache layer; **Apparatus's fake Redis-protocol server collides here — see `just demo-chimera` for the 16379 override pattern** |

## Integration seams

Each row is a unidirectional data flow. Read as "producer → wire → consumer".

| # | Producer | Protocol | Consumer | Maturity |
|---|---|---|---|---|
| 1 | Synapse WAF | WebSocket `/ws/sensors` (push) | Horizon API | ✅ works — wired via `HorizonManager::report_signal()` at `main.rs:2022` after the TASK-66 fix in `d43e552` |
| 2 | Synapse WAF | HTTP poll `/health`, `/stats`, `/waf/stats`, `/metrics` | Horizon API `synapse-direct.ts` | ✅ works — aggregate stats only, driven by `SYNAPSE_DIRECT_URL` env var |
| 3 | Apparatus | SSE `/sse` | Horizon API `apparatus-sse-bridge.ts` | ✅ works — driven by `APPARATUS_URL` env var |
| 4 | Horizon API | Prisma | PostgreSQL | ✅ production |
| 5 | Horizon API | WebSocket `/ws/dashboard` | Horizon UI | ✅ works |
| 6 | Horizon UI | REST `/api/v1/*` | Horizon API | ✅ works |
| 7 | Apparatus attack-sim | HTTP request (target URL is configurable) | any target | ✅ works — Apparatus is target-agnostic |
| 8 | Synapse WAF | HTTP forward | **upstream** (currently `127.0.0.1:5555` placeholder) | ⚠ **placeholder** — deferred until Chimera's Starlette migration lands; then swap to `127.0.0.1:8880` |
| 9 | Synapse WAF simulator | in-process Rust call | DetectionEngine + shared managers (`EntityManager`, `CampaignManager`, `BlockLog`, `WafStats`) | ✅ works — seam is `simulator::process_request` |
| 10 | Horizon API | typed client `@atlascrew/apparatus-lib` → REST | Apparatus's Flask/Express handlers | ⚠ partial — `/redteam/validate` has a POST/GET method mismatch that breaks the Red Team Scanner page |

## Maturity callouts

### Previously dormant, now awake
- **HorizonManager** (`apps/synapse-pingora/src/horizon/`, 1617 lines) — was built and compiled but never instantiated; `ProxyDependencies.horizon_manager: None, // not yet initialized in main` at both call sites. Woken in `d43e552`.
- **Apparatus SSE bridge** (`apps/signal-horizon/api/src/services/apparatus-sse-bridge.ts`) — fully implemented but gated on `APPARATUS_URL` being set in `.env`. Activated in `1f81fc9`.
- **Active Defense dashboards** (Breach Drills, Red Team Scanner, Supply Chain, Autopilot, JWT Testing) — React pages were written against `apparatus-lib` types but had no live backend to consume. Activated as a coherent section by grouping them in the sidebar (`ba229dd`) and running Apparatus (`1f81fc9`).

### Still dormant
- **TrendsManager background detection** (`apps/synapse-pingora/src/trends/manager.rs:76`) — `start_background_detection` is a stub loop. Synchronous detection via `record_request` / `record_payload_anomaly` works (TASK-55 wiring); batch detection does not. See `a5ffe35`.
- **`SessionDecision::Invalid` risk arm** (`main.rs:3366`) — the risk-contribution code path exists but `SessionManager::validate_request` never actually returns `Invalid`, so it's unreachable in production. See `task-67`'s documented skip.
- **Chimera Swagger spec** — `/apispec_1.json` only contains 1 route because Flasgger only picks up decorated endpoints, but Chimera registers 476 routes via blueprints. Not urgent; full spec generation is probably part of the Starlette migration.

### Placeholders awaiting behavior wiring
- **`config.horizon.yaml` upstream** — `upstreams: [{host: 127.0.0.1, port: 5555}]` is a placeholder because nothing listens on 5555 locally. The natural target is Chimera at 8880; deferred until the Starlette migration lands because gunicorn sync workers would become the pipeline's throughput ceiling.
- **`apparatus-lib` POST `/redteam/validate`** — cross-repo fix: either change the client call to GET (small) or add a POST handler in `../Apparatus/apps/apparatus/src/app.ts` (bigger). Defensive UI guard in place via `ed3e706`.

### In-flight migrations
- **Chimera: Flask/gunicorn/WSGI → Starlette/uvicorn/ASGI**. Status: `apps/vuln-api/app/asgi.py` exists alongside `app.py`; some blueprints are in flight. Expect route paths and response shapes to churn on pulls; re-probe after each `git pull` in `../Chimera`. Throughput ceiling moves 5-10× when this lands.

## Demo launchers

| Recipe | What it starts | Stops with |
|---|---|---|
| `just dev-horizon` | Horizon API + UI (no Synapse, no demo traffic) | `just dev-stop` |
| `just dev` | Horizon API + UI + Synapse WAF in dev mode (debug binary, no demo flag) | `just dev-stop` |
| `just demo` | Horizon API + UI + Synapse WAF (release, `--demo`) + Apparatus + Chimera | `just dev-stop` |
| `just demo-fleet` | Same as `just demo` plus Synapse WAF #2 and #3 (3-sensor fleet rendering) | `just dev-stop` + `just dev-stop-fleet` |
| `just demo-synapse` | Synapse WAF release binary only | `just dev-stop-one synapse-pingora` |
| `just demo-apparatus` | Apparatus only | `just dev-stop-one apparatus` |
| `just demo-chimera` | Chimera only | `just dev-stop-one chimera` |

All recipes run inside a shared `edge-protection` tmux session. `just dev-shell` attaches; `just dev-status` shows per-window health; `just dev-tail <name> <N>` tails any window.

## Pickup items (not urgent, worth remembering)

1. **Swap `config.horizon.yaml` upstream to Chimera** once Starlette migration lands — a one-line config change that unlocks "WAF blocks reach Chimera logs" A/B testing.
2. **Fix the `apparatus-lib` POST/GET mismatch** in `../Apparatus/libs/client/src/categories/security.ts` so Red Team Scanner works end-to-end.
3. **Teach Chimera's Flasgger spec generation** to emit all 476 routes, not just the one decorated endpoint.
4. **Add a `docs/architecture/data-flow.md`** with the full request lifecycle across the 10 seams above, once the upstream swap lands and every seam is load-bearing.
5. **Drain the dormant-but-wired list** — TrendsManager batch detection, `SessionDecision::Invalid` producer — both tracked in `backlog/tasks/task-66` and `task-67`.

## Update discipline

When you add a new service, wire, or maturity-state change, update this file in the same commit. It's easier to keep a one-page map current than to re-derive it from scratch later, and the "dormant vs placeholder vs in-flight" column is only valuable if it's trustworthy on the day you read it.
