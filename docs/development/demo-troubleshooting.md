# Demo Troubleshooting

Recovery recipes for issues that come up running the demo pipeline.
Paired with [demo-simulator.md](./demo-simulator.md) which covers the
architecture.

Each section is independent. Jump to whichever matches the symptom
you're seeing.

---

## Apparatus fails to start with `EADDRINUSE` on port 9000 or 6379

**Symptom.** The `apparatus` tmux window shows something like:
```
Error: listen EADDRINUSE: address already in use 127.0.0.1:9000
  code: 'EADDRINUSE',
  errno: -48,
  syscall: 'listen',
  address: '127.0.0.1',
  port: 9000
}
```

**Root cause.** Apparatus is a vulnerable-target simulator that spins up
multiple protocol servers (HTTP/1, HTTP/2, TCP echo, UDP echo, gRPC,
Bad SSL, MQTT, ICAP, Redis mock, SMTP sink, Syslog). Some of its
default ports collide with common local services:

- **Port 9000** is Apparatus's `PORT_TCP` (L4 TCP echo server).
  ClickHouse uses 9000 as its native TCP protocol port and will be
  holding it if you have ClickHouse running locally.
- **Port 6379** is Apparatus's `PORT_REDIS` (a fake Redis-protocol
  server for demos). Your local Redis server will be holding that.

**Fix.** The `just demo-apparatus` recipe already overrides these:
```bash
PORT_TCP=9100 PORT_REDIS=16379 pnpm --filter @atlascrew/apparatus dev
```

If you hit a different port conflict (e.g. your machine is running
another MQTT broker on 1883 or a Syslog daemon on 5514), override
the corresponding `PORT_*` env var in the recipe at
`justfile:demo-apparatus`. The full list of configurable ports is in
`../Apparatus/apps/apparatus/src/config.ts`.

---

## Horizon dashboards say "Apparatus integration disabled"

**Symptom.** Horizon API logs show:
```
INFO: Apparatus integration disabled (APPARATUS_URL not set)
INFO: Apparatus routes mounted at /api/v1/apparatus
```
And the Active Defense dashboards (Breach Drills, Red Team Scanner,
Supply Chain, Autopilot, JWT Testing) are empty even with Apparatus
running.

**Root cause.** Horizon's SSE bridge only initializes if
`APPARATUS_URL` is set in `apps/signal-horizon/api/.env` at Node
startup time. The `.env.example` has it commented out by default.

**Fix.**
```bash
echo 'APPARATUS_URL=http://127.0.0.1:8090' >> apps/signal-horizon/api/.env
```
Then **fully restart** the Horizon API — a tsx-watch child-restart is
not enough because the Node process reads `.env` only at true startup.
The easiest way to force a real restart is:
```bash
# Find and kill the tsx watcher and its child
pkill -9 -f "tsx.*watch src/index.ts"
pkill -9 -f "node.*signal-horizon-api/src"
# Relaunch in its tmux window
tmux send-keys -t edge-protection:signal-horizon-api 'cd apps/signal-horizon/api && pnpm dev' Enter
```

When the bridge is working you'll see:
```
INFO: Apparatus integration initialized
INFO: Apparatus SSE bridge initialized
INFO: Connecting to Apparatus SSE
INFO: Connected to Apparatus SSE stream
```

---

## Synapse WAF disappears after ~30-60 minutes with no crash log

**Symptom.** The WAF was running happily, the dashboard was populated,
and then everything stops. Nothing on ports 6190 or 6191. The
`synapse-pingora` tmux window shows something like:
```
zsh: killed     SYNAPSE_PRODUCTION=0 SYNAPSE_DEMO=1 ...
✘ KILL took 37m 26s  1
```
No panic message, no stack trace — the process was wiped by an
external SIGKILL.

**Root cause.** macOS's OOM killer. Debug-build synapse-waf is a
memory hog because Rust's `Drop` paths are not optimized away, and
the simulator's bounded-cache state (EntityManager, FingerprintIndex,
rotation detector history, schema learner templates) climbs toward
the configured caps. On a laptop with other apps running, the kernel
picks our process as the victim when memory pressure hits.

**Fix.** Use the **release** binary, not the debug binary. The
simplest way is:
```bash
just demo
```
which compiles `target/release/synapse-waf` on first run (a few
minutes) and runs that binary instead of the debug one. Release-built
synapse-waf has been observed running indefinitely under sustained
simulator load.

If you've been using `cargo run` or `./target/debug/synapse-waf`
manually, switch to:
```bash
cd apps/synapse-pingora
cargo build --release --bin synapse-waf
SYNAPSE_PRODUCTION=0 SYNAPSE_DEMO=1 SYNAPSE_ADMIN_AUTH_DISABLED=1 \
  RUST_LOG=warn,synapse_waf=info,synapse_waf::simulator=info \
  ./target/release/synapse-waf --config config.horizon.yaml --demo
```

**When to keep using debug.** If you're actively editing
`simulator.rs` or other Rust code, `just dev-synapse` uses the debug
binary so edit-compile-run is fast. Just don't leave the debug binary
running overnight expecting a populated demo in the morning — plan
to stop it after an hour of work.

---

## `/ws/dashboard` hangs on "Connecting…" in the browser

**Symptom.** Horizon dashboard loads, but every panel spins and the
browser devtools show the dashboard WebSocket stuck in the connecting
state. Aggregate panels and charts never render.

**Root cause (most common).** The Horizon API is alive but the Node
event loop is saturated by the simulator's signal firehose. Every
simulated request produces a `ThreatSignal` that Horizon's aggregator
ingests with an INSERT + SELECT + idempotency round-trip against
Prisma. At ~20 RPS the ingest queue grows faster than it can drain on
a dev box, and simple `/health` GETs / WebSocket upgrades can't get
past the backpressure.

**Diagnosis.**
```bash
# Is the API actually responsive?
curl -s --max-time 2 http://localhost:3100/health
# If that hangs or returns nothing, the event loop is choked.

# Is the simulator firing above the safe rate?
curl -s http://127.0.0.1:6191/_sensor/status \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['waf'])"
```

**Fix.**

1. Stop the synapse-waf window (`C-c` in its tmux window or
   `cortex tmux interrupt synapse-pingora`).
2. Restart the Horizon API to clear the backpressure queue. The
   simplest way is `tmux kill-window` + `tmux new-window` for that
   window, since the stuck Node child process won't respond to normal
   signals.
3. In `apps/synapse-pingora/src/simulator.rs`, confirm
   `tick_interval: Duration::from_millis(1000)` and
   `requests_per_tick: 2` (~4 RPS). If you bumped these for a perf
   test, revert them for normal demo use.
4. Rebuild (`cargo build --bin synapse-waf`) and restart the WAF in
   its tmux window with `--demo`.

**Don't exceed 10 RPS on a dev Horizon.** If you want a more active
demo, speed comes from adding more archetypes rather than turning up
the per-archetype rate.

---

## Horizon UI blank page / luma.gl version error

**Symptom.**
```
luma.gl: Found luma.gl 9.2.6 while initialzing 9.3.2
Uncaught Error: luma.gl - multiple versions detected
```
Page renders blank. Browser console shows the error at load.

**Root cause.** The UI's `package.json` had caret ranges (`^9.2.6`) on
`@luma.gl/*` and `@deck.gl/*`. pnpm's resolver satisfied the direct-dep
slots with 9.3.2 (the latest 9.x) but satisfied deck.gl's peer
constraint (`~9.2.6`, tilde) with 9.2.6. Two versions ended up loaded.

**Fix.** Tighten the ranges in `apps/signal-horizon/ui/package.json`
from `^9.2.6` to `~9.2.6` for every `@luma.gl/*` and `@deck.gl/*`
package, then reinstall:
```bash
cd "$REPO_ROOT"
pnpm install
```

This is already committed. If it resurfaces, something new added a
caret range — fix it the same way.

---

## Horizon API crashes on startup with `@prisma/client` error

**Symptom.** The `signal-horizon-api` tmux window shows:
```
SyntaxError: The requested module '@prisma/client' does not
  provide an export named 'Prisma'
```
and exits immediately. No port binding on 3100.

**Root cause.** The Prisma generated client is stale or missing. This
happens after a fresh clone, after changes to `schema.prisma`, or
after a `node_modules` wipe.

**Fix.**
```bash
cd apps/signal-horizon/api
pnpm db:generate
```

Then restart the API window. This is safe to re-run anytime and is
idempotent.

---

## `Auth failed: Invalid API key`

**Symptom.** synapse-waf logs, visible via
`cortex tmux dump synapse-pingora`:
```
ERROR [synapse_pingora::horizon::client] Auth failed: Invalid API key
```

**Root cause.** The `api_key` in `config.horizon.yaml` does not match
any row in the `sensor_api_keys` table for the target sensor.

**Fix.** Two options.

1. Use the canonical dev seed credentials. Ensure
   `config.horizon.yaml` has:
   ```yaml
   horizon:
     api_key: "sk-sensor-bridge-dev"
     sensor_id: "synapse-waf-1"
     sensor_name: "Synapse WAF"
   ```
   and the seed has run at least once:
   ```bash
   pnpm --filter @atlascrew/signal-horizon-api db:seed
   ```
2. If you want a custom sensor, create it in Postgres yourself and
   insert a `SensorApiKey` row whose `keyHash` matches
   `sha256(your_api_key)`.

The dev seed's constants are in
`apps/signal-horizon/api/prisma/seed/seed-postgres.ts` near the top of
the `seedTenant` function — search for `BRIDGE_SENSOR_*`.

---

## `Auth failed: New sensors must use a registration token`

**Symptom.** synapse-waf connects, passes the initial handshake, then
bounces with:
```
ERROR [synapse_pingora::horizon::client] Auth failed:
  New sensors must use a registration token. Generate one from the
  Fleet Management dashboard.
```

**Root cause.** Horizon's sensor gateway
(`apps/signal-horizon/api/src/websocket/sensor-gateway.ts` near line
727) looks up the existing sensor row by `(tenantId, name)` — not by
id. If `sensor_name` in `config.horizon.yaml` doesn't match the seeded
row's `name` column, the gateway treats the connection as a brand-new
sensor enrollment, which requires a one-time registration token
instead of a regular API key.

**Fix.** Ensure `sensor_name` is exactly `"Synapse WAF"` (with the
space, case-sensitive) in `config.horizon.yaml`:
```yaml
horizon:
  sensor_name: "Synapse WAF"
```
Matches `BRIDGE_SENSOR_NAME` in `prisma/seed/seed-postgres.ts`.

---

## `Auth failed: Sensor identity verification failed`

**Symptom.** Handshake and name lookup succeed, then:
```
ERROR [synapse_pingora::horizon::client] Auth failed:
  Sensor identity verification failed
```

**Root cause.** Known hole in the current demo wiring. The dev seed
populates `sensors.fingerprint` with
`sha256(sensor_id:api_key).slice(0, 32)` as a tamper-evident identity
anchor. Horizon's `verifySensorIdentity`
(`sensor-gateway.ts` around line 946) compares this column against a
`fingerprint` field the client is expected to send. `synapse-pingora`'s
`horizon::client` does not compute or send this value, so the
comparison fails for every first-connect.

**Workaround** (what we do for the demo). Null the fingerprint on the
seeded row. The gateway code at `sensor-gateway.ts` ~line 975 falls
through to "allow + populate on first connect" when
`existingSensor.fingerprint` is null:
```bash
/Applications/Postgres.app/Contents/Versions/latest/bin/psql \
  "postgresql://nick@localhost:5432/signal_horizon" \
  -c "UPDATE sensors SET fingerprint = NULL WHERE id = 'synapse-waf-1';"
```

**Follow-up (not yet done).** Either (a) teach `synapse-pingora`'s
horizon client to compute the same formula the seed uses, or (b)
change the seed to leave `fingerprint` null and rely on first-connect
to populate it. Option (b) is smaller and matches the code's own
intended fallback path. File a task when you're ready to fix it.

---

## `Signal channel closed; dropping signal`

**Symptom.** `cortex tmux dump synapse-pingora` shows a waterfall of:
```
WARN [synapse_pingora::horizon::client] Signal channel closed;
  dropping signal
```

**Root cause.** The `HorizonManager.report_signal` call reached the
client's internal mpsc channel, but the receiver side of that channel
has been dropped. This happens when the WebSocket background task
exits — almost always because an upstream auth error or connection
failure tore down the client.

**Diagnosis.** Look earlier in the same scrollback:
```bash
cortex tmux dump synapse-pingora | grep -E "Auth failed|Connection refused"
```

You'll find the real cause (one of the auth sections above, or
"Connection refused" meaning the Horizon API isn't on :3100).

**Fix.** Whatever the upstream cause was. Once the WAF successfully
authenticates to Horizon, the channel-closed warnings stop
immediately.

---

## Campaigns list → detail returns 404

**Symptom.** You click a campaign in the dashboard's campaigns list
and see:
```
GET /api/v1/synapse/{sensorId}/campaigns/cmny0w8br09qk680xpo9b7au6
→ 404 Campaign not found
```

**Root cause.** Horizon has **two campaign ID namespaces** that are
not reconciled:

1. **Sensor-local campaigns** — generated by synapse-waf's
   `CampaignManager` and served from its admin API. IDs look like
   `camp-19d89d644a0` (prefix + hex). They only live in the waf
   process's in-memory state.
2. **Seeded / fleet-wide campaigns** — stored in Horizon's Postgres
   by the dev seed and other ingest pipelines. IDs are Prisma cuids
   like `cmny0w8br09qk680xpo9b7au6`.

The campaigns **list page** mixes rows from both sources. The detail
page fetches via `/api/v1/synapse/{sensorId}/campaigns/{id}`, which
forwards to synapse-waf. synapse-waf never had the seeded cuid, so it
returns 404.

**Workaround.** Click campaigns whose IDs start with `camp-` — those
are live simulator-produced and the detail page resolves.

**Clean fix for a demo screenshot session.** Wipe the seeded
campaigns so the list only contains live-simulator entries:
```bash
/Applications/Postgres.app/Contents/Versions/latest/bin/psql \
  "postgresql://nick@localhost:5432/signal_horizon" \
  -c "DELETE FROM campaigns WHERE \"tenantId\" = 'tenant-acme-corporation';"
```
The simulator will re-populate `CampaignManager` on its next tick,
and Horizon's ingest will persist them to Postgres with live
synapse-waf IDs (prefix + hex). No more schism.

**Production fix** (not yet done). Horizon should either (a) persist
sensor-local campaigns to Postgres with their synapse-waf IDs so the
list and detail share a namespace, or (b) have the detail page
dereference cuids through the fleet-intel service instead of the
synapse-proxy path.

---

## Dashboard shows canned data like `185.220.101.42` or "actor_8f3a2b1c"

**Symptom.** Dashboard panels render, but the entities are
`185.220.101.42`, `45.155.205.233`, etc. — not the simulator's
`198.51.100.x` and `203.0.113.99`.

**Root cause.** You're hitting a canned fallback, not live data. Two
places these can fire:

1. **Horizon-side `demoMode` fallback**: services like
   `auth-coverage-aggregator.ts` return pre-baked demo data when the
   database is empty. Turn this off so the dashboard reads real rows
   directly. Look for `DEMO_MODE` or `demoMode` in
   `apps/signal-horizon/api/.env` or the service constructor defaults.
2. **synapse-waf admin fallback**: `admin_server.rs` has a handful of
   handlers that fall back to hardcoded JSON when their backing
   manager is empty. We left those in place as a safety net — they
   should only fire in the ~200ms window between WAF startup and the
   first simulator tick. If you're still seeing them after a minute of
   uptime, the simulator loop is not running (check the tmux window).

**Diagnosis.** Count simulator-origin rows in the database:
```bash
/Applications/Postgres.app/Contents/Versions/latest/bin/psql \
  "postgresql://nick@localhost:5432/signal_horizon" -c \
  "SELECT count(*), max(\"createdAt\") FROM signals
   WHERE \"sensorId\" = 'synapse-waf-1'
     AND metadata->>'source' = 'simulator';"
```
If that count is zero and the max is null, no simulator signals are
landing — the issue is upstream of the dashboard. If the count is
healthy but the dashboard still shows canned entities, a fallback is
intercepting.

---

## Cortex tmux `send` breaks with `TypeError: cannot use 'list' as a dict key`

**Symptom.**
```
$ cortex tmux send signal-horizon-api "pnpm dev"
TypeError: cannot use 'list' as a dict key (unhashable type: 'list')
```

**Root cause.** Upstream bug in `cortex tmux`. The `send` subcommand's
positional `command` arg is a list (from `nargs=+`), and the dispatch
table tries to use it as a dict key. The other subcommands (`read`,
`interrupt`, `running`, `keys`) are not affected.

**Workaround.** Use raw tmux directly:
```bash
tmux send-keys -t edge-protection:signal-horizon-api 'pnpm dev' Enter
```

File upstream when you have a moment; the fix is to rename the
positional to `cmd` or `text` in the argparse definition.

---

## Orphan Node process hangs on port 3100 after tmux window dies

**Symptom.** `lsof -iTCP:3100 -sTCP:LISTEN` shows a `node` process
listening but `ps` shows no parent, and the tmux window bound to the
API was killed. `cortex tmux running signal-horizon-api` may report
RUNNING even though the shell in the window is dead.

**Root cause.** A `tsx watch` child process was detached from its
parent shell when the window was killed with `tmux kill-window`. It
keeps the TCP socket open because `nx` and `tsx` don't always
propagate SIGTERM through the process tree.

**Fix.**
```bash
# Kill anything tsx-watching the signal-horizon-api source
pkill -9 -f "tsx.*signal-horizon-api"
pkill -9 -f "node.*signal-horizon-api/src"
# Also kill by pid if pkill misses it
kill -9 <pid>
```
Then recreate the window fresh:
```bash
tmux new-window -t edge-protection: -n signal-horizon-api \
  -c "/Users/nick/Developer/Edge Protection/apps/signal-horizon/api"
tmux send-keys -t edge-protection:signal-horizon-api 'pnpm dev' Enter
```
