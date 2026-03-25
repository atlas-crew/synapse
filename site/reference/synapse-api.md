---
title: Synapse Admin API Reference
---

# Synapse Admin API

The Synapse admin API runs on port `6191` by default and provides runtime management endpoints.

## Authentication

All admin endpoints require the `X-Admin-Key` header matching the `admin_api_key` in `config.yaml`. If no key is configured, a random key is generated at startup and logged.

```sh
curl http://localhost:6191/status -H "X-Admin-Key: $ADMIN_KEY"
```

## Health & Status

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/status` | Runtime status and health information |
| `GET` | `/metrics` | Prometheus-format metrics |

**`GET /status` response:**

```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "workers": 4,
  "rules_loaded": 237,
  "entities_tracked": 1523,
  "requests_processed": 458201
}
```

## Configuration

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/config` | Get current runtime configuration |
| `POST` | `/config` | Update runtime configuration fields |
| `POST` | `/reload` | Hot-reload configuration from file (~240 μs) |

**Hot-reload:**

```sh
curl -X POST http://localhost:6191/reload -H "X-Admin-Key: $ADMIN_KEY"
```

```json
{
  "status": "reloaded",
  "duration_us": 240
}
```

## Entity Management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/entities` | List tracked entities with risk scores |
| `POST` | `/block` | Block an IP or fingerprint |
| `POST` | `/release` | Release a blocked entity |
| `POST` | `/release-all` | Release all blocked entities |

**Block an IP:**

```sh
curl -X POST http://localhost:6191/block \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "manual block"}'
```

**List entities:**

```sh
curl http://localhost:6191/entities -H "X-Admin-Key: $ADMIN_KEY"
```

```json
{
  "entities": [
    {
      "ip": "192.168.1.100",
      "risk_score": 85,
      "blocked": true,
      "first_seen": "2026-03-23T10:00:00Z",
      "last_seen": "2026-03-23T14:30:00Z",
      "request_count": 450
    }
  ]
}
```

## WAF Rules

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/rules` | List loaded WAF rules |
| `POST` | `/rules/add` | Add a custom rule |
| `POST` | `/rules/remove` | Remove a rule by ID |
| `POST` | `/rules/clear` | Clear all custom rules |
| `POST` | `/evaluate` | Test a request against the rule engine |

**Evaluate a test request:**

```sh
curl -X POST http://localhost:6191/evaluate \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"path": "/api/users?id=1 OR 1=1", "method": "GET"}'
```

```json
{
  "risk_score": 85,
  "matched_rules": ["200200"],
  "action": "block",
  "detection_time_us": 25
}
```

## Site Management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/_tenant/sites` | List all configured sites |
| `POST` | `/_tenant/sites` | Create new site |
| `GET` | `/_tenant/sites/:id` | Get site configuration |
| `PUT` | `/_tenant/sites/:id` | Update site configuration |
| `DELETE` | `/_tenant/sites/:id` | Remove site |
| `PUT` | `/_tenant/sites/:hostname/waf` | Update WAF config (threshold, rule overrides) |
| `PUT` | `/_tenant/sites/:hostname/rate-limit` | Update rate limit (RPS, burst) |

Config changes apply immediately via graceful reload — zero dropped connections.

## Actor & Session Tracking

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/_sensor/actors` | List tracked actors |
| `GET` | `/_sensor/actors/stats` | Actor statistics summary |
| `GET` | `/_sensor/actors/:id` | Actor details with composite identity |
| `GET` | `/_sensor/sessions` | List active sessions |
| `GET` | `/_sensor/sessions/stats` | Session statistics |
| `GET` | `/_sensor/sessions/:id` | Session details with hijack alerts |

## Profiling & Payload

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/debug/profiles` | View all learned profiles (what the WAF is thinking) |
| `GET` | `/_sensor/profiling/stats` | Profiling statistics |
| `GET` | `/_sensor/profiling/templates` | Learned path templates |
| `GET` | `/_sensor/profiling/baselines` | Endpoint baselines |
| `GET` | `/_sensor/profiling/schemas` | Learned API schemas |
| `GET` | `/_sensor/payload/stats` | Payload statistics |
| `GET` | `/_sensor/payload/bandwidth` | Global bandwidth + timeline |
| `GET` | `/_sensor/payload/endpoints` | Per-endpoint payload stats |
| `GET` | `/_sensor/payload/entities` | Top entities by bandwidth |
| `GET` | `/_sensor/payload/anomalies` | Payload anomalies |

## Campaigns & Signals

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/_sensor/campaigns` | List detected campaigns |
| `GET` | `/_sensor/campaigns/stats` | Campaign statistics |
| `GET` | `/_sensor/campaigns/:id` | Campaign details |
| `GET` | `/_sensor/campaigns/:id/actors` | Actors in campaign |
| `GET` | `/_sensor/campaigns/:id/timeline` | Campaign event timeline |
| `GET` | `/_sensor/signals` | List signals |
| `GET` | `/_sensor/signals/stats` | Signal statistics |
| `GET` | `/_sensor/signals/anomalies` | Signal anomalies |
| `GET` | `/_sensor/trends` | Trend data |

## Interrogator & DLP

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/_sensor/interrogator/stats` | All interrogator statistics |
| `GET` | `/_sensor/interrogator/tarpit` | Tarpit statistics |
| `GET` | `/_sensor/interrogator/challenges` | Challenge statistics |
| `GET` | `/_sensor/injection/stats` | Injection tracker statistics |
| `GET` | `/_sensor/injection/headless` | Headless browser detections |
| `GET` | `/_sensor/dlp/stats` | DLP scanning statistics |
| `GET` | `/_sensor/dlp/patterns` | Active DLP patterns |

## Persistence

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/_sensor/persistence/stats` | Persistence statistics |
| `POST` | `/_sensor/persistence/save` | Force immediate state save |
| `GET` | `/_sensor/persistence/export` | Export full state |
| `POST` | `/_sensor/persistence/import` | Import state |

::: info Automatic persistence
Learned profiles snapshot to `data/profiles.json` automatically. WAF retains intelligence across restarts — no cold-start learning period.
:::

## Authentication Model

| Setting | Behavior |
| --- | --- |
| `admin_api_key` set | Write endpoints require `Authorization: Bearer <token>` |
| No key configured | Read-only endpoints (health, metrics, stats) accessible without auth |

Read-only endpoints (`GET /health`, `/metrics`, `/sites`, `/stats`) do not require authentication. All write endpoints (`POST`, `PUT`, `DELETE`) require the admin API key.

## Prometheus Metrics (40+)

`GET /metrics` returns Prometheus-format metrics. Key categories:

**Request counters:**

| Metric | Type |
| --- | --- |
| `synapse_requests_total` | Counter |
| `synapse_requests_by_status{status="2xx\|3xx\|4xx\|5xx"}` | Counter |
| `synapse_requests_blocked` | Counter |

**Latency histogram:**

| Metric | Description |
| --- | --- |
| `synapse_request_duration_us_bucket{le="X"}` | Cumulative buckets (100 μs to 1 s) |
| `synapse_request_duration_us_sum` | Total latency microseconds |
| `synapse_request_duration_us_count` | Total observations |

**WAF metrics:**

| Metric | Type |
| --- | --- |
| `synapse_waf_analyzed` | Counter |
| `synapse_waf_blocked` | Counter |
| `synapse_waf_challenged` | Counter |
| `synapse_waf_logged` | Counter |
| `synapse_waf_detection_avg_us` | Gauge |
| `synapse_waf_rule_matches{rule_id="X"}` | Counter (per-rule) |

**Profiling/anomaly:**

| Metric | Type |
| --- | --- |
| `synapse_profiles_active_count` | Gauge |
| `synapse_anomalies_detected_total{type="X"}` | Counter |
| `synapse_avg_anomaly_score` | Gauge (0–10) |
| `synapse_requests_with_anomalies` | Counter |

**Backend:**

| Metric | Type |
| --- | --- |
| `synapse_backend_requests{backend="X"}` | Counter |
| `synapse_backend_healthy{backend="X"}` | Gauge (0/1) |
| `synapse_uptime_seconds` | Gauge |
