---
name: edge-protection-demo
description: Launch, monitor, and troubleshoot the Edge Protection demo and fleet environments. Use when running just recipes (demo, demo-fleet, dev) or diagnosing service connectivity and performance issues.
---

# Edge Protection Demo Pilot

This skill provides the procedural knowledge required to orchestrate the multi-service Edge Protection platform in development and demo modes.

## Bundled Utilities

- **`scripts/check_health.cjs`**: Verifies both process availability and HTTP health endpoints for the entire stack.
  - Usage: `node scripts/check_health.cjs`

## Workflow

### 1. Launching Environments

Use the `just` recipes to start tmux-backed services:
- **`just dev`**: Standard development environment (Horizon + Synapse).
- **`just demo`**: Full stack with release-build Synapse and procedural traffic.
- **`just demo-fleet`**: Multi-sensor fleet demo (3 Synapse instances).

**Tip**: Use `just dev-shell` to attach to the `edge-protection` tmux session.

### 2. Monitoring Health

Run the health check utility to verify all services are active:
```bash
node scripts/check_health.cjs
```

- **`just dev-status`**: Check which services are running, idle, or stopped.
- **`just dev-tail <name>`**: View the last 50 lines of logs for a specific service.
- **`just services`**: Verify local infrastructure (Redis, Postgres, ClickHouse) is UP.

### 3. Troubleshooting Common Issues

See [Service Troubleshooting](references/services.md) for detailed recovery recipes.

- **EADDRINUSE**: Apparatus often collides on ports 9000 (ClickHouse) and 6379 (Redis). Use `just demo-apparatus` which applies correct overrides.
- **Horizon 404s**: Usually means the Prisma client is stale. Run `just db-generate`.
- **WAF Silence**: If the WAF is running but no signals appear, check the `APPARATUS_URL` in Horizon's `.env` and ensure the API key in `config.horizon.yaml` is correct.
- **OOM Kills**: Debug-build Synapse WAF is memory-intensive. Always use `just demo` (release build) for long-running sessions.

## Best Practices

- **Resource Management**: Limit simulator traffic to < 10 RPS on dev machines to avoid saturating the Node.js event loop.
- **Clean State**: If the demo data feels "stale" or "split", wipe the campaigns table in Postgres to let the simulator re-populate fresh IDs.
- **Process Cleanup**: If a service hangs, use `pkill -9 -f <pattern>` or `just dev-reset` to clear the tmux session and orphan processes.

## Resources

- [Service Troubleshooting](references/services.md): Port map, common failure modes, and recovery commands.
- `docs/development/demo-troubleshooting.md`: Canonical project troubleshooting guide.
- `docs/development/demo-simulator.md`: Architecture of the procedural traffic generator.
