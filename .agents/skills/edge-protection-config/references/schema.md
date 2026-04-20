# Config Schema

Canonical top-level sections in a Synapse WAF config file:

## `server` (required)

```yaml
server:
  listen: "127.0.0.1:6190"       # Proxy port (public-ish)
  admin_listen: "127.0.0.1:6191" # Admin + observability port
  workers: 0                     # 0 = auto (one per core)
  waf_threshold: 75              # Aggregate score for block decision
  waf_enabled: true
  trusted_proxies:
    - "127.0.0.1/32"
```

## `upstreams` (required)

```yaml
upstreams:
  - host: "127.0.0.1"
    port: 5555
```

## `rate_limit`

```yaml
rate_limit:
  rps: 10000
  enabled: true
```

## `logging`

```yaml
logging:
  level: "info"        # trace | debug | info | warn | error
  format: "text"       # text | json
  access_log: true
```

## `detection`

```yaml
detection:
  sqli: true
  xss: true
  path_traversal: true
  command_injection: true
  action: "block"      # block | monitor | alert
  block_status: 403
```

## `telemetry`

```yaml
telemetry:
  enabled: false
  endpoint: "http://localhost:3100/telemetry"
  api_key: null
  batch_size: 100
  flush_interval:
    secs: 10
    nanos: 0
```

## `horizon` (hub client)

Appears in fleet configs. Connects the sensor to the Synapse Fleet hub.

```yaml
horizon:
  endpoint: "wss://fleet.example/hub"
  sensor_id: "sensor-01"
  api_key: "env:SYNAPSE_FLEET_KEY"
```

## `tunnel`

Optional — encrypted tunnel to the hub when direct WSS is unavailable.

## `waf`, `dlp`, `entity_tracking`, `session`

Subsystem-specific config. See the corresponding module in `src/` for the full schema. Changes here go through `ConfigManager` like any other write.

## Validation Rules

- Every sub-system must validate its own slice on reload. A subsystem that doesn't validate is a bug.
- Unknown fields should be rejected at parse time (serde `deny_unknown_fields`). This catches typos.
- Port collisions across fleet configs (e.g. `config.horizon.yaml` and `config.horizon.2.yaml` both using `6190`) are always a bug.
