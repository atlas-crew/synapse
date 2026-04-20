# Hot Reload Integration

## The Atomic Swap Contract

Synapse WAF's config is held in a global `Arc<RwLock<Config>>`. Mutations must go through `ConfigManager::update_*` so the swap is atomic:

1. `ConfigManager` builds a fully-validated candidate config.
2. Every subsystem (WAF engine, DLP, rate limiter, admin server) validates the candidate.
3. If all validators pass, the `Arc` is swapped in one operation.
4. If any validator fails, the swap is rolled back; no subsystem sees a partial update.

## What Write Handlers Must Do

```rust
async fn update_site_handler(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateSite>,
) -> impl IntoResponse {
    state.config_manager
        .update_site(&id, body)   // ← goes through validation + swap
        .await?;
    Ok(Json(json!({"ok": true})))
}
```

## What Write Handlers Must NOT Do

- Call `state.config.write().await` directly. The swap bypasses validation.
- Hold a `RwLockWriteGuard` across `.await` points. Deadlock risk.
- Mutate nested fields without rebuilding the parent. Cloning is cheap at config scale.
- Skip validation on "small" changes. All writes go through the same gate.

## Failure Modes

| Symptom                                   | Cause                                       | Fix                              |
|-------------------------------------------|---------------------------------------------|----------------------------------|
| Sensor returns 200 but config not applied | Write held the lock but didn't swap         | Use `ConfigManager`              |
| Reload succeeds, next request panics      | Partial update left a subsystem inconsistent| Rebuild via `ConfigManager`      |
| Reload hangs                              | Held write lock across await                | Don't do that                    |
| Admin console shows stale values          | Reads went through cached snapshot          | Re-fetch after write response    |

## Testing

Test write handlers through the Router (so middleware + `ConfigManager` both run), not by calling the handler function directly. See examples in `admin_server.rs` test modules.
