# Synapse-Pingora Admin API Reference

Admin server default port: **6191**

---

## Authentication

All `/_sensor/*` endpoints and mutation endpoints (POST/PUT/DELETE) require the `X-Admin-Key` header.

```
X-Admin-Key: <your-admin-key>
```

In dev mode (`--dev`), authentication is bypassed.

---

## Common Query Parameters

Most list endpoints support:

| Parameter | Type   | Description          |
|-----------|--------|----------------------|
| `limit`   | int    | Max results returned |
| `offset`  | int    | Pagination offset    |
| `sort`    | string | Sort field           |
| `order`   | string | `asc` or `desc`      |
| `filter`  | string | Filter value         |

---

## Response Format

All endpoints return JSON. Errors use:

```json
{"error": "message"}
```

---

## Core Operations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | API info |
| GET | `/health` | Health check |
| GET | `/_sensor/health` | Health check (sensor path) |
| GET | `/metrics` | Prometheus metrics |
| GET | `/console` | Admin web console |
| POST | `/reload` | Reload configuration |
| POST | `/test` | Test config (dry-run) |
| POST | `/restart` | Restart service |
| GET | `/stats` | Runtime statistics |

---

## Configuration Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/config` | Get full config |
| POST | `/config` | Update full config (hot reload) |
| GET | `/_sensor/config` | Dashboard config view |
| GET | `/_sensor/config/export` | Export as YAML |
| POST | `/_sensor/config/import` | Import from YAML/JSON |
| GET | `/_sensor/config/dlp` | Get DLP config |
| PUT | `/_sensor/config/dlp` | Update DLP config |
| GET | `/_sensor/config/block-page` | Get block page config |
| PUT | `/_sensor/config/block-page` | Update block page config |
| GET | `/_sensor/config/crawler` | Get crawler detection config |
| PUT | `/_sensor/config/crawler` | Update crawler detection config |
| GET | `/_sensor/config/tarpit` | Get tarpit config |
| PUT | `/_sensor/config/tarpit` | Update tarpit config |
| GET | `/_sensor/config/travel` | Get impossible travel config |
| PUT | `/_sensor/config/travel` | Update impossible travel config |
| GET | `/_sensor/config/entity` | Get entity store config |
| PUT | `/_sensor/config/entity` | Update entity store config |
| GET | `/_sensor/config/integrations` | Get external integrations |
| PUT | `/_sensor/config/integrations` | Update external integrations |
| GET | `/_sensor/config/kernel` | Get kernel/sysctl parameters |
| PUT | `/_sensor/config/kernel` | Update kernel/sysctl parameters |

---

## Site Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sites` | List sites |
| POST | `/sites` | Create site |
| GET | `/sites/{hostname}` | Site details |
| PUT | `/sites/{hostname}` | Update site |
| DELETE | `/sites/{hostname}` | Delete site |
| PUT | `/sites/{hostname}/waf` | Update site WAF config |
| PUT | `/sites/{hostname}/rate-limit` | Update site rate limit |
| PUT | `/sites/{hostname}/access-list` | Update site access list |
| GET | `/sites/{hostname}/shadow` | Get shadow mirror config |
| PUT | `/sites/{hostname}/shadow` | Update shadow mirror config |

---

## WAF & Detection

| Method | Path | Description |
|--------|------|-------------|
| GET | `/waf/stats` | WAF statistics |
| POST | `/_sensor/evaluate` | Dry-run WAF evaluation |
| GET | `/_sensor/rules` | List active rules (supports filtering) |
| POST | `/_sensor/rules` | Create rule |
| PUT | `/_sensor/rules/{rule_id}` | Update rule |
| DELETE | `/_sensor/rules/{rule_id}` | Delete rule |
| GET | `/_sensor/blocks` | Recent block events |
| GET | `/_sensor/access-lists` | CIDR allow/deny lists |

---

## Entity & Actor Intelligence

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/entities` | Top entities by risk |
| DELETE | `/_sensor/entities/{ip}` | Release/unblock entity |
| POST | `/_sensor/entities/release-all` | Release all entities |
| GET | `/_sensor/actors` | Actor list with behavioral data |
| GET | `/_sensor/actors/{actor_id}` | Actor detail |
| GET | `/_sensor/actors/{actor_id}/timeline` | Actor timeline |
| GET | `/_sensor/sessions` | Sessions with hijack detection |
| GET | `/_sensor/sessions/{session_id}` | Session detail |
| GET | `/_sensor/stuffing` | Credential stuffing data |

---

## Threat Intelligence & Campaigns

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/signals` | Intelligence signals |
| POST | `/_sensor/report` | Ingest external signals |
| GET | `/_sensor/campaigns` | Active campaigns |
| GET | `/_sensor/campaigns/{id}` | Campaign detail |
| GET | `/_sensor/campaigns/{id}/actors` | Campaign actors |
| GET | `/_sensor/campaigns/{id}/graph` | Correlation graph |
| GET | `/_sensor/campaigns/{id}/timeline` | Campaign timeline |
| GET | `/_sensor/trends` | Trend data |
| GET | `/_sensor/anomalies` | Anomaly events |

---

## Profiling & Analytics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/profiling/templates` | Endpoint templates |
| GET | `/_sensor/profiling/baselines` | Traffic baselines |
| GET | `/_sensor/profiling/schemas` | Schema info |
| GET | `/_sensor/profiling/schema/discovery` | Discovery events |
| GET | `/_sensor/profiling/anomalies` | Endpoint anomalies |
| GET | `/_sensor/payload/bandwidth` | Bandwidth stats |
| GET | `/_sensor/dlp/stats` | DLP scanner stats |
| GET | `/_sensor/dlp/violations` | Recent DLP violations |
| GET | `/api/profiles` | Endpoint profiles |
| GET | `/api/profiles/{template}` | Profile detail |
| GET | `/api/schemas` | Learned schemas |
| GET | `/api/schemas/{template}` | Schema detail |
| POST | `/api/profiles/reset` | Reset profiles |
| POST | `/api/schemas/reset` | Reset schemas |

---

## System & Diagnostics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/status` | Dashboard status |
| GET | `/_sensor/system/config` | System configuration |
| GET | `/_sensor/system/overview` | System overview metrics |
| GET | `/_sensor/system/performance` | Performance metrics |
| GET | `/_sensor/system/network` | Network stats |
| GET | `/_sensor/system/processes` | Process info |
| GET | `/_sensor/system/logs` | System logs |
| GET | `/_sensor/logs` | All logs with filtering |
| GET | `/_sensor/logs/{source}` | Logs by source |
| GET | `/_sensor/diagnostic-bundle` | Export diagnostic bundle |
| POST | `/_sensor/metrics/reset` | Reset all metrics |
| GET | `/_sensor/certificates` | TLS certificates |
| GET | `/_sensor/bot-indicators` | Bot detection metrics |
| GET | `/_sensor/header-profiles` | Header anomaly stats |

---

## Shadow Mirroring

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/shadow/status` | Shadow mirror status |

---

## Demo & Debug

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_sensor/demo` | Demo mode status |
| POST | `/_sensor/demo/toggle` | Toggle demo mode |
| GET | `/debug/profiles` | Debug endpoint profiles |
| POST | `/debug/profiles/save` | Force save profiles |
| GET | `/_sensor/debugger/ws` | WebSocket WAF debugger |
