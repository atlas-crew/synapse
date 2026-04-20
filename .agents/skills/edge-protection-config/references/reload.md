# Hot-Reload Semantics

## The Flow

```
Admin API POST /reload
     │
     ▼
ConfigManager::reload()
     │
     ├─► Parse candidate YAML
     ├─► Run schema validation (serde + custom validators)
     ├─► Ask each subsystem: "validate this config slice"
     │       - WAF engine validates rules
     │       - DLP validates patterns
     │       - Rate limiter validates rps/bursts
     │       - Admin server validates scope defs
     │
     ├─► All passed? ──► Atomic Arc swap ──► Notify subscribers ──► 200 OK
     │
     └─► Any failed? ──► Drop candidate ──► 4xx with error list
```

## Atomicity

The swap is one operation: all of the state transitions to the new config, or none of it does. Subsystems that cache derived state must invalidate on the swap notification, not on the next read.

## Failure Modes and Fixes

| Symptom                                    | Likely Cause                              | Fix                                    |
|--------------------------------------------|-------------------------------------------|----------------------------------------|
| Reload returns 200, behavior unchanged     | Handler mutated clone, didn't call swap   | Route through `ConfigManager`          |
| Reload returns 4xx, sensor now degraded    | Validation passed partially               | Ensure validators are pure (no side effects until swap) |
| Reload hangs                               | Write lock held across `.await`           | Rebuild outside the lock; hold only during swap |
| Post-reload telemetry missing              | ClickHouse retry buffer wasn't told to flush | Have telemetry subscribe to swap notifications |
| Reload succeeds, but admin console 500s    | Admin scope defs changed but handlers hold stale refs | Ensure admin state uses `Arc` reads, not captured values |

## Writing a New Subsystem Validator

1. Implement `Validator` (or whatever the trait is named in this repo — check `reload.rs`).
2. Pure function: no side effects until the swap succeeds.
3. Return rich errors — the reload response should tell operators exactly what failed.
4. Add a test that reloads a known-bad config and asserts the correct error.

## Testing Hot Reload

- Unit-test the candidate-validation path independently of the swap.
- Integration-test via the admin API: `curl -X POST http://127.0.0.1:6191/reload`.
- Chaos-test: reload under load. The swap should never cause dropped in-flight requests.
