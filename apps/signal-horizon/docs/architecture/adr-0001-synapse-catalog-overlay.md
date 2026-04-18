# ADR 0001 — Synapse catalog + tenant overlay for WAF rule distribution

- **Status:** Accepted
- **Date:** 2026-04-17
- **Related:** TASK-76 (Load Synapse WAF rule catalog (248) into Horizon and push full bodies to sensors), TASK-45 (Restore 237 production WAF rules from archive), memory `project_dashboard_federation.md`

## Context

Synapse-Pingora ships an authoritative ruleset — currently 248 rules — in `apps/synapse-pingora/src/production_rules.json`. The file is the single source of truth for the Rust sensor's WAF engine: at boot each sensor reads it directly and deserializes it into `Vec<WafRule>`.

Horizon is the fleet-management plane that distributes rules to sensors. Before this change Horizon could not do that job in practice:

- No Horizon table stored the 248 Synapse rules.
- The one rule model that did exist (`CustomerRule`) only represented tenant-authored rules. Its field set (`severity`, `action`, `patterns`, `sensitivity`) did not map onto the Synapse rule shape (`id:u32`, `risk`, `contributing_score`, `blocking`, `classification`, `state`, `version_support`, nested `matches` boolean tree).
- `RuleDistributor.distributeRules()` contained a placeholder at `rule-distributor.ts:337-345` that emitted `{id: string, name, enabled, conditions:{}, actions:{}}` with *no rule body*. Even setting aside the empty bodies, `Rule.id: string` with cuid-like values could never have deserialized on the sensor, because `WafRule.id` is `u32` — serde rejects strings there.

Tenants also need to tune catalog rules — disable a noisy rule, override blocking mode, adjust risk — without forking the vendor ruleset.

## Decision

Split rule state into three tables with clear ownership:

1. **`SynapseRule`** — canonical mirror of `production_rules.json`. Immutable per catalog version, globally scoped (no tenantId). Columns capture the indexable subset (`classification`, `state`, `risk`, `blocking`, `beta`) plus a `rawDefinition Json` blob that stores the full imported rule body verbatim. `catalogVersion` + `catalogHash` stamp every row with the catalog release they came from. Primary key is `ruleId INTEGER` — the Synapse numeric id itself, because it is already globally unique and is the key sensors use on the wire.

2. **`TenantRuleOverride`** — per-tenant overlay on a catalog rule. All override columns (`enabled`, `blockingOverride`, `sensitivityOverride`, `riskOverride`) are nullable; null means "inherit the catalog value." Unique `(tenantId, synapseRuleId)` so there is exactly one override row per tenant-rule pair. Cascade delete: dropping a catalog row removes every tenant's override on it.

3. **`CustomerRule`** — unchanged. Tenant-authored rules that are not in the Synapse catalog.

On push, the `RuleDistributor.buildRulePushPayload()` helper does the merge:

```
catalog(rawDefinition) ⊕ override(per-column precedence) ∪ custom(translated)
```

Override values win over the catalog when set; nulls fall through. Overrides with `enabled=false` filter rules out of the push entirely.

## Consequences

### Operational

- Importing `production_rules.json` is a two-step op: run the Prisma migration (new tables) then `pnpm -C apps/signal-horizon/api run rules:sync` (populates the catalog). The loader records a `catalogHash` computed from a canonical-form JSON so whitespace-only reformats of the source do not register as a new catalog version.
- Sensors reconcile by hash, not by rule count. Growing from 248 → 251 rules does not require coordinating a magic number; it is just a hash change.
- Delete semantics: if Synapse removes a rule from `production_rules.json`, the next sync prunes it from `SynapseRule` and cascades away any tenant overrides on that id. If audit trail becomes important later, introduce a soft-delete `deprecatedAt` column rather than changing the cascade.

### Separation of concerns

- **Catalog is vendor property, overrides are tenant property.** A Synapse upgrade cannot silently overwrite tenant tuning, because tuning never touches the catalog row. Conversely, a misbehaving tenant cannot wedge their copy of a catalog rule — the canonical body is one JSON column away, always.
- **The `rawDefinition` blob is a deliberate loose contract.** Synapse adds a new rule field tomorrow and the loader keeps working, because unknown fields ride along in the blob and get pushed to sensors verbatim. Adding Zod validation to the loader would be a trap: it would start rejecting rules the moment the vendor shape evolves. Columns are only materialized for fields that need indexing or filtering from the fleet UI.

### Sensor compatibility

- The Rust WAF rule deserializer (`apps/synapse-pingora/src/waf/rule.rs`) tolerates unknown fields and requires only `id:u32`, `description:string`, `matches:Vec<MatchCondition>`. All three survive the merge. The push payload is therefore the exact same shape as a raw `production_rules.json` array, and the sensor's code path for "loaded from Horizon push" converges with "loaded from disk."

### Known limitations

- Pagination in `GET /api/v1/fleet/rules/available?source=all` is per-source, not across the merged stream. Fine for the current 248+small-custom-set case; if custom sets grow large this needs a unified cursor.
- `RuleSyncState.ruleId` remains `String`, shared between catalog and custom rules. A numeric foreign key from `RuleSyncState` to `SynapseRule` would be cleaner but would block custom-rule sync rows. Resolving that is scope for a follow-up.
- Drift detection compares expected hash against the sensor's reported `rulesHash` (published in heartbeat via `FleetAggregator.sensorMetrics`). That value is not persisted in Prisma today — drift is live-only. If a historical drift timeline is needed, add a `Sensor.rulesHash` column and backfill on heartbeat.

## Rejected alternatives

- **Extend `CustomerRule` to hold catalog rules.** Would have required adding a `source` column and widening half the existing fields to nullable, with no way to stop tenant edits from shadowing vendor upgrades.
- **Store catalog rules in a Json column on `Tenant`.** Duplicates 248 rows into every tenant, scales poorly, and offers no index on classification/state for UI filtering.
- **Surrogate cuid PK on `SynapseRule`.** Would force every sensor-side identifier translation through a lookup. The Synapse numeric id is already globally unique and authoritative; a surrogate would be a useless layer of indirection.
- **Hash the raw `production_rules.json` file bytes for `catalogHash`.** Loses stability under whitespace-only reformats; we chose a canonical-form hash (rules sorted by id, keys sorted per rule).

## References

- Migration: `apps/signal-horizon/api/prisma/migrations/20260417093000_add_synapse_rule_catalog/`
- Schema: `apps/signal-horizon/api/prisma/schema.prisma` (`SynapseRule`, `TenantRuleOverride`)
- Loader: `apps/signal-horizon/api/src/services/synapse-rule-loader.ts`
- Distributor merge: `apps/signal-horizon/api/src/services/fleet/rule-distributor.ts::buildRulePushPayload`
- Sensor receiver: `apps/synapse-pingora/src/horizon/client.rs` (`HubMessage::PushRules`)
- Sensor rule shape: `apps/synapse-pingora/src/waf/rule.rs`
