# Service Architecture & Troubleshooting

This reference maps the Edge Protection service ecosystem and its dependencies.

## Port Assignments

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| **Horizon API** | 3100 | HTTP | Fleet management control plane. |
| **Horizon UI** | 5180 | HTTP | React/Vite dashboard. |
| **Synapse WAF #1**| 6190 | HTTP | Proxy port for Sensor #1. |
| **Synapse WAF #1**| 6191 | HTTP | Admin API for Sensor #1. |
| **Apparatus** | 8090 | HTTP/1 | Active Defense backend (SSE bridge). |
| **Apparatus** | 8443 | HTTP/2 | Active Defense backend. |
| **Chimera** | 8880 | HTTP | Purpose-built vulnerable target. |
| **Redis** | 6379 | TCP | Session and queue management. |
| **PostgreSQL** | 5432 | TCP | Relational configuration state. |
| **ClickHouse** | 8123 | HTTP | Telemetry and time-series data. |

## Common Failure Recipes

### 1. `EADDRINUSE` (Apparatus)
**Symptom**: `just demo-apparatus` fails with port conflicts.
**Fix**: Use the `just` recipe which applies these overrides:
- `PORT_TCP=9100` (avoids ClickHouse 9000).
- `PORT_REDIS=16379` (avoids local Redis 6379).

### 2. Horizon API Start Failure (`@prisma/client`)
**Symptom**: `SyntaxError: The requested module '@prisma/client' does not provide an export...`
**Fix**: Regenerate the Prisma client:
```bash
cd apps/signal-horizon/api && pnpm db:generate
```

### 3. Missing Active Defense Signals
**Symptom**: "Apparatus integration disabled" in Horizon logs.
**Fix**: Ensure `APPARATUS_URL` is in `apps/signal-horizon/api/.env`.
```bash
APPARATUS_URL=http://127.0.0.1:8090
```

### 4. Synapse OOM (SIGKILL)
**Symptom**: `synapse-pingora` tmux window exits with code 1 after 30-60 mins.
**Fix**: Run the release build using `just demo` instead of `just dev-synapse`.

### 5. Simulator Signal Storm
**Symptom**: Dashboard panels hang on "Connecting…".
**Fix**: Revert `apps/synapse-pingora/src/simulator.rs` to safe rates:
- `tick_interval`: 1s.
- `requests_per_tick`: 2-4 RPS max.
