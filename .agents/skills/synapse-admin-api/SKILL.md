---
name: synapse-admin-api
description: Author, review, and modify Axum endpoints on the Synapse WAF admin API. Use when adding, changing, or auditing handlers in apps/synapse-pingora/src/admin_server.rs or its supporting modules.
---

# Synapse Admin API Strategy

The Synapse WAF exposes an Axum-based admin + observability API on port `:6191` (per-config). `admin_server.rs` is a single large module with 90+ handlers, a layered auth/scope system, and tight integration with the hot-reload machinery.

## Auth & Scope Model

Every handler goes through one of the scope guards defined in `admin_server.rs`:

- `require_auth` — base authentication (API key or session).
- `require_ws_auth` — WebSocket-specific auth upgrade.
- `require_admin_read` / `require_admin_write` — read-only vs write admin.
- `require_config_write` — gated on config mutation.
- `require_service_manage` — restart/reload/service lifecycle.
- `require_sensor_read` / `require_sensor_write` — sensor-scoped operations.
- `check_scope` — core scope predicate used by the guards above.

Rate limiting is split: `rate_limit_admin` (stricter) vs `rate_limit_public`. `audit_log` middleware records every mutating request. `security_headers` wraps responses.

## Handler Conventions

- Handlers are `async fn <name>_handler(...) -> impl IntoResponse`.
- State is threaded as `State(state): State<AdminState>`.
- Path params use `Path<T>`; body params use `Json<T>`.
- Write handlers must run under `require_*_write` and call into `config_manager` / `reload.rs` for config changes — never mutate config directly.
- Handler grouping follows the resource (sites, sensors, stats, WAF, shadow, reload, health, metrics).

## Bundled Utilities

- **`scripts/audit_admin_routes.cjs`**: Scans `admin_server.rs` for handlers missing a scope guard. Flags any `.route("/...", <method>(<handler>))` whose handler function doesn't appear downstream of a `require_*` layer.
  - Usage: `node scripts/audit_admin_routes.cjs`

## Workflow

1. **Design**: Decide which scope guard applies. Default to the most restrictive that still allows the intended caller.
2. **Handler**: Implement `async fn <name>_handler` returning `impl IntoResponse`. Return typed errors via the existing error enum, not ad-hoc `StatusCode` mappings.
3. **Wire**: Mount under the correct Router group with the right `require_*` layer and `rate_limit_*`.
4. **Reload**: For config changes, go through `config_manager::ConfigManager::update_*` so hot-reload atomicity holds. Never `write()` config state directly.
5. **Test**: Add a handler test that calls through the Router (not the function directly) so middleware runs.

## Resources

- [Scope Matrix](references/scopes.md): Full mapping of guards to allowed operations.
- [Hot Reload Integration](references/hot-reload.md): How write handlers must interact with `config_manager` and `reload.rs`.
