# Scope Matrix

## Scope Guards

| Guard                    | Reads | Writes | Notes                                       |
|--------------------------|-------|--------|---------------------------------------------|
| `require_auth`           | ✓     | ✓      | Base — always required                      |
| `require_admin_read`     | ✓     |        | General admin reads                         |
| `require_admin_write`    |       | ✓      | General admin writes                        |
| `require_config_write`   |       | ✓      | Must route through `config_manager`         |
| `require_service_manage` |       | ✓      | Restart, reload, service lifecycle          |
| `require_sensor_read`    | ✓     |        | Sensor telemetry / status queries           |
| `require_sensor_write`   |       | ✓      | Sensor commands / config push               |
| `require_ws_auth`        | ✓     | ✓      | WebSocket upgrade handshake                 |

## Resource → Guard Mapping

| Resource family        | Read                 | Write                  |
|------------------------|----------------------|------------------------|
| `/sites`, `/site/:id`  | `require_admin_read` | `require_config_write` |
| `/sensors`             | `require_sensor_read`| `require_sensor_write` |
| `/reload`, `/restart`  | —                    | `require_service_manage`|
| `/stats`, `/health`    | `require_auth` (public-ish) | —               |
| `/waf/*`               | `require_admin_read` | `require_config_write` |
| `/shadow/*`            | `require_admin_read` | `require_config_write` |
| `/metrics`             | `require_auth`       | —                      |

## Rules

- **Default deny**: If you can't find a guard that fits, you need a new one — don't reuse a weaker guard.
- **Write always implies read.** Writers don't need to compose both.
- **Config writes must touch `ConfigManager`.** Raw `RwLock` mutation is a bug.
- **WebSocket upgrade** must use `require_ws_auth`, not `require_auth`, because the handshake differs.
