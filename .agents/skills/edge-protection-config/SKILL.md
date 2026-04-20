---
name: edge-protection-config
description: Manage per-sensor YAML configuration files for Synapse WAF (config.horizon.yaml and fleet variants) and interact safely with the hot-reload machinery. Use when adding a new fleet sensor config, tuning thresholds, or modifying config_manager.rs / reload.rs behavior.
---

# Edge Protection Config & Hot-Reload Strategy

Synapse WAF loads its runtime config from a YAML file, with multiple configs coexisting in `apps/synapse-pingora/` for fleet-demo scenarios. Config mutations are driven through `config_manager.rs` and applied atomically by `reload.rs`.

## Config File Layout

- **`config.horizon.yaml`**: The canonical dev/demo config (sensor #1, ports `6190/6191`).
- **`config.horizon.2.yaml`**: Sensor #2 (ports `6290/6291`).
- **`config.horizon.3.yaml`**: Sensor #3 (ports `6390/6391`).

Each config has the same top-level sections: `server`, `upstreams`, `rate_limit`, `logging`, `detection`, `telemetry`, plus optional `waf`, `dlp`, `entity_tracking`, `session`, `tunnel`, `horizon` (hub client).

## Rules for Adding a New Sensor Config

1. Copy from an existing `config.horizon.N.yaml` as the template.
2. Bump every port by `+100` (so admin and proxy never collide on the same host).
3. Set a unique `sensor_id` under `telemetry` / `horizon` sections.
4. Add a matching `just dev-synapse-N` / `just demo-synapse-N` recipe if you expect to run the sensor via tmux.

## Hot-Reload Machinery

- **`config_manager.rs`**: Owns the canonical `Arc<RwLock<Config>>`. All updates go through `ConfigManager::update_*` methods.
- **`reload.rs`**: Provides the atomic swap and signal handling. Do not read/write the config `Arc` directly from handlers.
- **Atomic swap contract**: A reload must succeed completely (all sub-systems validate the new config) or roll back. Partial updates are a bug.
- **Admin API path**: Every `require_config_write` handler in `admin_server.rs` must route through `ConfigManager`, never mutate the `Arc` directly.

## Bundled Utilities

- **`scripts/validate_fleet_configs.cjs`**: Parses every `config.horizon*.yaml`, verifies no port collisions, checks required fields, and confirms each sensor has a unique `sensor_id`.
  - Usage: `node scripts/validate_fleet_configs.cjs`

## Workflow

1. **Edit/Add**: Update YAML under `apps/synapse-pingora/`.
2. **Validate**: Run the bundled script. Also `cargo test --test config_validation` if you touched the schema.
3. **Test hot reload**: `curl -X POST http://127.0.0.1:6191/reload` against a running sensor. Confirm atomic swap in the logs.
4. **Commit**: Config + any matching `justfile` recipe in one atomic commit.

## Resources

- [Config Schema](references/schema.md): Required fields, defaults, and sub-system mapping.
- [Reload Semantics](references/reload.md): Atomicity contract, failure modes, rollback behavior.
