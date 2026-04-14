# Demo Mode

Demo mode runs a full Horizon + Synapse stack on your machine with
**synthetic attacker traffic** driving the real detection engine. The
dashboards light up with live entities, campaigns, block events, and
signal correlation as if a real sensor were protecting real users —
but no network traffic ever leaves your laptop.

Use it to explore Horizon's analyst experience, evaluate the WAF's
behavior against known attack patterns, capture screenshots and
recordings, or build your own detection rules against a predictable
adversary.

## What you get

When the demo is running you'll see:

- **Two procedural attackers**
  - **Credential stuffer** — 20 source IPs in `198.51.100.0/24` all
    sharing one JA4 TLS fingerprint, cycling usernames against a login
    endpoint. The dashboards show it as a growing JA4 IP-cluster
    campaign, which is exactly how a real credential-stuffing botnet
    reveals itself.
  - **Vulnerability scanner** — one source IP (`203.0.113.99`) with
    an `sqlmap/1.7.2` User-Agent hitting classic SQLi, XSS, path
    traversal, and command-injection payloads. Trips production
    blocking rules immediately and climbs to maximum entity risk
    within seconds.
- **Real engine verdicts**, not canned responses. Rule matches,
  risk scores, block decisions, and correlation all come from the
  exact same code that runs in production.
- **Real Horizon pipeline**. Signals flow through Synapse's WebSocket
  telemetry client into Horizon's sensor gateway and land in
  PostgreSQL, which is what the per-actor and per-campaign dashboards
  read from.

## Telling demo data from real data

The demo is built on **RFC 5737 reserved IP blocks** (`198.51.100.0/24`
and `203.0.113.0/24`) which are guaranteed never to appear in real
internet traffic. If you see one of those IPs in a dashboard, it's
100% simulator-origin.

Every demo signal also carries `metadata.source = "simulator"` in its
JSON body, and block log entries fall back to `reason = "simulator"`
when no specific rule reason is set. You can always filter demo data
out of an analyst view with a single query.

## Requirements

- Rust toolchain (`rustup` with a recent stable)
- Node 20+ and `pnpm`
- Postgres 15+ (or Postgres.app) running locally
- `tmux` (we use it to manage the three local services cleanly)

## Quick start

From the repo root:

```bash
# 1. Install JS dependencies
pnpm install

# 2. Generate the Prisma client and apply migrations
pnpm --filter @atlascrew/signal-horizon-api db:generate
pnpm --filter @atlascrew/signal-horizon-api db:migrate

# 3. Seed the Horizon database with the dev tenant and sensor rows
#    This creates the "synapse-waf-1" sensor identity that the demo
#    connects as, plus demo campaigns, threats, and actors.
pnpm --filter @atlascrew/signal-horizon-api db:seed

# 4. Enable the Apparatus SSE bridge in horizon's .env so the Active
#    Defense dashboards receive drill / red team / supply chain events.
#    (Skip this if you don't have the Apparatus repo cloned as a
#    sibling directory — the demo still works without it.)
echo 'APPARATUS_URL=http://127.0.0.1:8090' >> apps/signal-horizon/api/.env

# 5. Start the full demo stack (builds a release Synapse binary on
#    first run, then launches Horizon API + UI + Synapse WAF +
#    Apparatus across four tmux windows)
just demo
```

The first run compiles the release Synapse binary, which takes a few
minutes. Subsequent runs are near-instant because cargo is incremental
and the Horizon tsx watcher is already warm.

::: tip Why release and not debug?
The debug build is a memory hog (Rust's `Drop` code isn't optimized
away, and bounded caches still accumulate up to their caps) and
macOS's OOM killer picks it off after ~30-60 minutes of continuous
simulation on a laptop. The release build runs indefinitely. If you
want to hack on the Synapse code and iterate quickly, use
`just dev-synapse` instead — it uses the debug binary which compiles
faster but won't stay alive as long.
:::

Then open **`http://localhost:5180`** in your browser. Within a few
seconds the aggregate panels start moving and
shortly after the per-actor and per-campaign panels populate with
entities from the reserved IP ranges above.

The first time you log in, use the seeded admin credentials from the
seed output — search for `adminEmail` and `adminPassword` in the seed
script's log output, or run the seed command again and capture them.
For the acme tenant (the default) they are:

```
Email:    admin+acme-corporation@signal-horizon.dev
Password: dev-acme-corporation-admin
```

## What's actually running

Demo mode ties three processes together:

| Service | tmux window | Port | Role |
|---|---|---|---|
| Horizon API | `signal-horizon-api` | 3100 | REST + WebSocket gateways, Postgres ingestion |
| Horizon UI | `signal-horizon-ui` | 5180 | Dashboard (Vite dev server) |
| Synapse WAF | `synapse-pingora` | 6190 / 6191 | Real detection engine + `--demo` traffic generator |
| Apparatus | `apparatus` | 8090 / 8443 | Active Defense backend (drills, red team, supply chain) |

All three live inside a shared tmux session (default name
`edge-protection`). Attach with `just dev-shell` to see all three
log streams side by side, or use:

- `just dev-status` — quick status check of all three windows
- `just dev-tail synapse-pingora 100` — tail the last 100 lines from
  the Synapse window
- `just dev-stop` — stop everything (kills all three windows)
- `just dev-restart` — stop + start — useful after you rebuild

The traffic generator calls the real `DetectionEngine` and updates
real state managers for entities, campaigns, block logs, and WAF
statistics. Horizon polls the WAF admin API for aggregate numbers and
receives per-signal pushes via a WebSocket. The UI reads both.

Under the hood this means you are exercising exactly the same code
paths a production sensor would — the simulator is not a mock of the
WAF, it is the WAF being fed synthetic requests through a side channel.

## Tuning the demo

Defaults generate ~4 requests per second, which is sustainable
indefinitely against a laptop. If you want a busier demo:

- Open `apps/synapse-pingora/src/simulator.rs`
- Adjust `tick_interval` (default `1000ms`) or `requests_per_tick`
  (default `2`) in `SimulatorLoop::new`
- Rebuild and restart the WAF

Do not exceed **10 RPS** on a dev machine. Horizon's signal aggregator
does an INSERT + SELECT + idempotency round-trip against Prisma for
every signal, and the Node event loop will saturate at higher rates —
symptom is the dashboard WebSocket hanging at "Connecting…". More
archetype variety is a better way to make the demo feel alive than
higher RPS on a small set of archetypes.

## Common issues

- **"luma.gl: multiple versions detected"** in the browser on first
  load → run `pnpm install` from the repo root. This should be fixed
  in the committed lockfile; if it reappears, a new dependency added a
  caret range on `@luma.gl/*` or `@deck.gl/*`.
- **Horizon API crashes with `Prisma` import error** → run
  `pnpm --filter @atlascrew/signal-horizon-api db:generate`.
- **"Connecting…" forever in the dashboard** → check that the Synapse
  WAF process is actually running and not silently backpressured (see
  the RPS note above).
- **"Auth failed: Sensor identity verification failed"** in the WAF
  logs → run the seed again, then null the fingerprint column on the
  seeded sensor row:
  ```sql
  UPDATE sensors SET fingerprint = NULL WHERE id = 'synapse-waf-1';
  ```

Detailed diagnosis and recovery recipes for these (and more) live in
the repo under `docs/development/demo-troubleshooting.md`.

## Where to go next

- **Try a rule change.** The WAF's production rule set lives in
  `apps/synapse-pingora/src/production_rules.json`. Edit a rule, rebuild,
  restart the WAF, and watch the simulator's traffic react in real
  time.
- **Add your own archetype.** Implement the `Archetype` trait in
  `apps/synapse-pingora/src/simulator.rs`, add an instance to
  `SimulatorLoop::new`, rebuild.
- **Read the architecture doc.** For contributors,
  `docs/development/demo-simulator.md` in the repo covers the simulator's
  design decisions, state-mirror seam, HorizonManager wake-up, and
  known limitations.
