# Synapse Admin Console — Configuration Audit

Inventory of every piece of configuration and observability surface the
Synapse sensor exposes via its admin API, mapped to the current admin
console's panel coverage. The goal is to identify what operators can
inspect or change through `/console` versus what they can only reach
via `curl`.

**Method:** walked the `ConfigFile` struct in `apps/synapse-pingora/
src/config.rs`, enumerated every `.route(…)` in `admin_server.rs`, and
compared to the panel list in `admin_console.html`.

**TL;DR:** The admin API exposes **89 distinct (method, path)
endpoints** (GET:60, POST:13, PUT:13, DELETE:3) across 55 unique
paths; the admin console surfaces ~15 of them. **Coverage is ~17%.**
The biggest blind spots are per-site CRUD, access control / header
manipulation editors, profiler tuning, and the entire observability
stack (signals, actors, campaigns, anomalies, trends).

**Endpoint breakdown by prefix:**
- `/_sensor/*` — 63 endpoints (bulk of the admin API: signals, actors,
  campaigns, config modules, diagnostics, rules, profiler, etc.)
- `/sites/*` — 9 endpoints (per-site CRUD + WAF/rate-limit/access-list/
  shadow subroutes — all invisible in the UI)
- `/api/*` — 5 endpoints (profiler schemas + profiles)
- `/console*` — 2 endpoints (the HTML console + sidebar lockup SVG)
- `/config` — 2 endpoints (global config GET + POST)
- Root singletons — 8 endpoints (`/`, `/health`, `/waf/stats`,
  `/restart`, `/metrics`, `/test`, `/stats`, `/reload`)

---

## A. Observability (read-only)

Sensor-side data the API surfaces for inspection.

| Surface | API | In console? | Notes |
|---|---|---|---|
| Overview stats | `/stats` | ✅ Overview panel | `total_requests`, `blocked_requests`, `rate_limited`, `active_connections` |
| WAF stats | `/waf/stats` | ✅ WAF Stats panel | SQLi / XSS / path traversal / cmd injection counters |
| Full config dump | `/config` | ✅ Overview panel | Raw JSON pretty-printed |
| Sensor status | `/_sensor/status` | ❌ | Rich sensor-level health + lifecycle data |
| Signals feed | `/_sensor/signals` | ❌ | Detection events with metadata |
| Anomalies | `/_sensor/anomalies` | ❌ | Behavioural anomaly detections |
| Campaigns | `/_sensor/campaigns` | ❌ | Correlated attack campaigns |
| Actors | `/_sensor/actors` | ❌ | IP/fingerprint actor entities |
| Sessions | `/_sensor/sessions` | ❌ | Active session tracking |
| Entities | `/_sensor/entities` | ❌ | WAF-tracked entities |
| Trends | `/_sensor/trends` | ❌ | Time-bucketed trend data |
| Blocks | `/_sensor/blocks` | ❌ | Historical block decisions |
| Credential stuffing | `/_sensor/stuffing` | ❌ | Stuffing-attempt clustering |
| Access lists | `/_sensor/access-lists` | ❌ | Sensor-level CIDR view |
| Certificates | `/_sensor/certificates` | ❌ | TLS cert inventory |
| Profiler schemas | `/api/schemas` | ❌ | Learned request-body schemas |
| Profiler profiles | `/api/profiles` | ❌ | Endpoint behaviour profiles |
| DLP stats | `/_sensor/dlp/stats` | ❌ | Scan counts, match counts |
| Payload bandwidth | `/_sensor/payload/bandwidth` | ❌ | Throughput metrics |
| Shadow mirror status | `/_sensor/shadow/status` | ❌ | Mirror traffic stats |
| System logs | `/_sensor/system/logs`, `/_sensor/logs`, `/_sensor/logs/:src` | ❌ | Sensor + access logs |
| Report / bundle | `/_sensor/report`, `/_sensor/diagnostic-bundle` | ❌ | Aggregated diagnostics |
| Metrics | `/metrics` | ❌ | Prometheus-style metrics |
| Rule browser | `/_sensor/rules` | ❌ | WAF rule inventory |

**Gap:** 20+ observability endpoints have zero UI — operators must
curl them. Most critical: signals / actors / campaigns / anomalies
(the core threat-intel outputs) and logs (first thing anyone looks at
when debugging).

---

## B. Global Configuration

Top-level `ConfigFile.server` (`GlobalConfig` struct) + `rate_limit` +
`profiler`.

| Field | Exposed in? | In console? |
|---|---|---|
| `server.http_addr` | `/config` read | ❌ |
| `server.https_addr` | `/config` read | ❌ |
| `server.workers` | `/config` read | ❌ |
| `server.shutdown_timeout_secs` | `/config` read | ❌ |
| `server.waf_threshold` | `/config` read | ❌ |
| `server.waf_enabled` | `/config` read | ❌ |
| `server.log_level` | `/config` read | ❌ |
| `server.admin_api_key` | `/config` read (redacted?) | ❌ |
| `server.trap_config` (honeypot) | `/config` read | ❌ |
| `server.waf_regex_timeout_ms` | `/config` read | ❌ |
| `rate_limit.rps` | `/config` read/write | ✅ Rate Limiting |
| `rate_limit.enabled` | `/config` read/write | ✅ Rate Limiting |
| `rate_limit.burst` | `/config` read/write | ❌ (field exists in response, not in form) |
| `profiler.*` (10 fields) | `/config` read | ❌ |

**Gap:** Only 2 of ~15 global settings are editable in the UI. Most
critical unexposed: `waf_threshold`, `waf_enabled`, `log_level`,
`trap_config`, and the entire profiler anomaly threshold panel.

### `detection` block (from example YAML — not a typed struct)

The console's Detection panel reads from `cfg.detection.{sqli, xss,
path_traversal, command_injection, action, block_status}` — but no
matching `DetectionConfig` struct exists in `config.rs`. These fields
are probably synthesised from runtime rule-activation state or live
in an implicit location not yet mapped. **Worth investigating:** is
the Detection panel actually saving anything, or is the POST
silently discarded?

---

## C. Site Configuration (per-host)

`SiteYamlConfig` per host — the meat of a production deployment.

| Sub-config | API coverage | Console coverage |
|---|---|---|
| `hostname` | CRUD via `/sites` | Read-only list |
| `upstreams` | CRUD via `/sites` | Read-only in site detail |
| `tls` (cert/key/min_version) | via `/sites/:host` | ❌ (global TLS panel exists but it's site-0 not multi-site) |
| `waf` (enabled/threshold/rule_overrides) | `PUT /sites/:host/waf` | ❌ |
| `rate_limit` (per-site) | `PUT /sites/:host/rate-limit` | ❌ |
| `access_control` (CIDR allow/deny) | `PUT /sites/:host/access-list` | ❌ |
| `headers` (add/set/remove req+resp) | via `/sites/:host` | ❌ |
| `shadow_mirror` | `GET/PUT /sites/:host/shadow` | ❌ |

**Gap:** The Sites panel is **read-only** despite the API supporting
full CRUD. Every site-level tuning knob — WAF threshold, rule
overrides, per-site rate limits, access control, header rewrites,
shadow mirroring — is invisible to the operator unless they use the
Raw API panel.

**Single highest-leverage gap in the whole audit:** making Sites a
real editor. Production operators spend most of their time here.

---

## D. Module Configuration

Sub-system configs reached via `/_sensor/config/<module>`.

| Module | API | In console? |
|---|---|---|
| DLP | `/_sensor/config/dlp` | ✅ Modules panel |
| Tarpit | `/_sensor/config/tarpit` | ✅ Modules panel |
| Crawler Detection | `/_sensor/config/crawler` | ✅ Modules panel |
| Entity Tracking | `/_sensor/config/entity` | ✅ Modules panel |
| Integrations | `/_sensor/config/integrations` | ✅ Modules panel |
| Block Page | `/_sensor/config/block-page` | ❌ (API exists, not in `MODULE_ENDPOINTS`) |
| Travel | `/_sensor/config/travel` | ❌ (API exists, not in `MODULE_ENDPOINTS`) |
| Kernel params | `/_sensor/config/kernel` | ❌ |

**Gap:** Two module endpoints (`block-page`, `travel`) are trivially
two lines in the `MODULE_ENDPOINTS` array. `kernel` is more involved
because it controls sysctls and may have write safety concerns worth
surfacing explicitly.

The current Modules panel also has a **silent data-loss bug**: it
uses `Object.entries(cfg).filter(([, v]) => typeof v !== 'object')`
which strips out nested config (DLP patterns, integration endpoints,
etc.). Save-round-trip drops nested values. Needs recursive fields or
a JSON-editor fallback for complex modules.

---

## E. Runtime Operations

| Action | API | In console? |
|---|---|---|
| Reload config | `POST /reload` | ✅ Actions panel |
| Test config | `POST /test` | ✅ Actions panel |
| Restart | `POST /restart` | ✅ Actions panel |
| Export config | `GET /_sensor/config/export` | ✅ Actions panel |
| Import config | `POST /_sensor/config/import` | ❌ (endpoint exists, button missing) |
| Demo mode toggle | `GET/POST /_sensor/demo` | ❌ |
| Metrics reset | `POST /_sensor/metrics/reset` | ❌ |
| Evaluate (dry-run) | `POST /_sensor/evaluate` | ❌ |

**Gap:** Export exists but import doesn't. Demo mode toggle, metrics
reset, and dry-run evaluate are operationally useful primitives that
aren't surfaced.

---

## F. Proposed Reorganisation

Current IA: three sections (Monitor / Configure / Admin) with 9 panels.

Suggested IA for the post-audit console, organised by operator
workflow rather than by API tree:

### Observe
- **Overview** — stats + health + recent activity
- **Signals** — detection events feed (new)
- **Actors** — IP/fingerprint entity view (new)
- **Campaigns** — correlated attacks (new)
- **Anomalies** — behavioural outliers (new)
- **Trends** — time-bucketed graphs (new)
- **Logs** — filterable log viewer (new)

### Site Operations
- **Sites** — CRUD editor (upgrade from read-only)
- **Site Detail** — tabs for WAF / Rate Limit / TLS / Access Control
  / Headers / Shadow Mirror / Rule Overrides (all new)

### Global Configuration
- **Server** — threshold, workers, log level, shutdown, regex timeout (new)
- **Detection** — current behaviour (verify POST actually persists)
- **Rate Limit** — global fallback
- **Trap / Honeypot** — honeypot endpoint config (new)
- **Profiler** — anomaly thresholds (new)

### Modules
- **DLP**, **Tarpit**, **Crawler**, **Entity**, **Integrations** —
  current (fix nested-field data loss)
- **Block Page**, **Travel**, **Kernel** — new

### System
- **Certificates**, **Access Lists**, **Rules**, **Schemas/Profiles**,
  **Diagnostic Bundle** — all new

### Admin
- **Operations** (reload/test/restart/metrics-reset)
- **Config Import / Export** (add import)
- **Demo Mode** toggle (new)
- **Raw API** — keep

---

## G. Prioritised Implementation Order

Ranked by leverage (how many unblocked workflows per hour of work):

| Priority | Item | Why |
|---|---|---|
| 1 | **Sites full CRUD + per-site config tabs** | Biggest single gap. Production operators live here. |
| 2 | **Signals / Actors / Campaigns observability panels** | Core threat-intel outputs that currently require curl |
| 3 | **Fix Modules panel nested-field data loss** | Silent bug — config saves drop data |
| 4 | **Detection panel audit** — does POST actually persist? | Possible zombie endpoint |
| 5 | **Add missing module configs** (block-page, travel, kernel) | 2 lines in `MODULE_ENDPOINTS` + a panel for kernel |
| 6 | **Global server settings panel** | Currently invisible unless operators know the YAML |
| 7 | **Logs viewer** | Debuggability 101 |
| 8 | **Profiler tuning panel** | 10 thresholds currently hand-edited in YAML |
| 9 | **Config import button** | Export exists; import endpoint exists; just need the button |
| 10 | **Access Control / Headers / Shadow Mirror editors** | Covered by Sites panel work in item 1 |

---

## H. Structural Questions Worth Answering Before Building

Before committing to a redesign, three questions benefit from upfront
decisions rather than discovery during implementation:

1. **Where does `detection` config actually live?** The Detection
   panel posts to `/config` with a `detection:` block, but no struct
   in `config.rs` accepts it. Either (a) the POST is silently
   discarded today, or (b) there's an implicit mapping to
   per-site WAF rule-activation that the Rust side handles. Resolve
   before investing in a Detection redesign.

2. **Should this stay an embedded HTML page, or graduate to a
   bundled SPA?** Currently it's ~720 lines of HTML + inline JS.
   Expanding to a Sites editor with tabbed per-site config pushes
   that toward 3000+ lines. The single-file embed constraint was
   load-bearing for sensor standalone deployability, but at some
   size, a bundled-in-binary Vite build (served from assets/) becomes
   more maintainable. **Threshold to decide:** when the
   `admin_console.html` file first exceeds ~1500 lines. Current: 722.

3. **Do we share component code with the Synapse Dashboard (Horizon
   UI)?** The dashboard has `<Panel>`, `<SectionHeader>`,
   `<DataTable>`, etc. in React. The admin console can't consume React
   directly without bundling. But the visual vocabulary (tones,
   colors, spacing) is the same — we could codify the shared design
   tokens as a CSS variables file that both consume. Brand
   reorganisation (in flight) is a natural place to do this.

---

*Generated 2026-04-17 as a pre-work audit for the Synapse admin
console expansion. Supersedes the Tier 2/3 items in
`docs/development/plans/ui-brand-backlog.md` for the admin console.*

---

## Addendum — Horizon Dashboard already covers the module configs

Follow-up investigation after the initial audit revealed that Horizon's
React codebase already has **fully-built editors** for most of the
per-module config the admin console's Modules panel exposes. They live
at `apps/signal-horizon/ui/src/components/fleet/pingora/`:

- `WafConfig` — rendered in sensor-detail Pingora tab
- `RateLimitConfig` — rendered in sensor-detail Pingora tab
- `AccessControlConfig` — rendered in sensor-detail Pingora tab
- `ServiceControls` — rendered in sensor-detail Pingora tab
- `AdvancedConfigPanel` — composite editor bundling DLP / Block Page /
  Crawler / Tarpit / Entity & Travel (previously rendered only on the
  separate `SensorConfigPage` advanced surface)
- `DlpConfig`, `BlockPageConfig`, `CrawlerConfig`, `TarpitConfig`,
  `EntityConfig` — **fully built React editors with validation and
  typed state, wired internally by `AdvancedConfigPanel` but unreachable
  from the main `/fleet/sensors/:id/config` flow until wiring was added
  in commit `<NEXT>`**

### Action taken

Wired `<AdvancedConfigPanel>` into the sensor-detail Pingora sub-tab
below the existing WAF / RateLimit / AccessControl editors. One
component wraps all five module configs in a sidebar-tabbed layout.
State hydrates from `remotePingoraConfig.advanced` when the API
returns it; falls back to `defaultAdvancedConfig` otherwise.

### Impact on the audit conclusions

The previous "build module config editors in the Synapse admin console"
framing was wrong. Horizon has the editors — they just weren't wired
into the main sensor config page. This shifts the admin console's
strategic scope:

- **Admin console = local recovery tool.** Minimum viable surface for
  air-gapped / pre-tunnel / recovery-mode scenarios. Reload, restart,
  test, health, import/export, raw API. Keep it small.
- **Horizon = primary config workbench.** Owns the rich editors for
  WAF, rate limit, access control, DLP, tarpit, crawler, entity,
  travel, block page. Continues to grow as the operator's go-to.

### Revised priorities

The Section G priority table should be re-read with this in mind:

| Original priority | Revised status |
|---|---|
| 1. Sites full CRUD + per-site tabs | Still valid; partially covered by sensor-detail Pingora tab (now with advanced config). Gap remaining: Sites *list* CRUD + headers editor + shadow mirror editor. |
| 2. Observability panels (signals/actors/campaigns) | Dashboard already covers — admin console can skip. |
| 3. Fix Modules panel nested-field data loss | Still valid for the admin console's existing Modules panel, but **lower priority now** because operators can use Horizon's richer editors. |
| 4. Detection panel audit | Still valid — investigate where `detection` config actually lives. |
| 5. Missing modules (block-page, travel, kernel) | Block Page + Travel now surfaced via Horizon's `AdvancedConfigPanel`. Admin console adding them is lower priority. Kernel is still admin-console-first (dangerous ops, local-recovery context). |
| 6. Global server settings panel | Lower priority — Horizon's `SensorConfigPage` with `AdvancedConfigPanel` + its "Advanced JSON Editor" escape hatch already covers this in an operator-friendly way. |
| 7. Logs viewer | Still valid. Dashboard has limited log surfacing today. |

**New highest-priority item:** the Sites list on Horizon is still
read-only. The components for editing site-level WAF / rate limit /
access control EXIST (the Pingora tab uses them), but the Sites page
itself doesn't edit sites — you can only view a site and then navigate
to its sensor-detail page. A top-level Sites CRUD experience is the
single biggest remaining gap.
