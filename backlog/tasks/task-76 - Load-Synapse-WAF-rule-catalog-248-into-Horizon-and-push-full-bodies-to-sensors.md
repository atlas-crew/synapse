---
id: TASK-76
title: >-
  Load Synapse WAF rule catalog (248) into Horizon and push full bodies to
  sensors
status: To Do
assignee: []
created_date: '2026-04-17 09:26'
labels:
  - horizon
  - synapse
  - waf
  - federation
  - schema
dependencies: []
references:
  - apps/synapse-pingora/src/production_rules.json
  - apps/synapse-pingora/src/waf/rule.rs
  - apps/synapse-pingora/src/rules.rs
  - 'apps/signal-horizon/api/prisma/schema.prisma:1318-1397'
  - 'apps/signal-horizon/api/src/services/fleet/rule-distributor.ts:309-369'
  - 'apps/signal-horizon/api/src/services/synapse-proxy.ts:66-90'
  - 'apps/signal-horizon/api/src/schemas/synapse.ts:70-93'
  - apps/signal-horizon/api/src/api/routes/fleet.ts
  - apps/signal-horizon/api/src/api/routes/beam/rules.ts
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
## Problem

Horizon cannot currently distribute the full Synapse WAF ruleset to sensors:

- The 248 production rules live in `apps/synapse-pingora/src/production_rules.json`. Horizon has no loader, no persistent store, and no import/sync path for them.
- Horizon's only rule model is `CustomerRule` (Prisma `beam_rules`) — tenant-authored custom rules. Its fields (`severity`, `action`, `patterns`, `sensitivity`) do not map cleanly onto the Synapse rule shape (`id:u32`, `risk`, `matches[]` boolean tree, `classification`, `version_support`, `blocking`, `state`).
- `apps/signal-horizon/api/src/services/fleet/rule-distributor.ts:337-345` is a stub. It pushes placeholder `{id, name, enabled, conditions:{}, actions:{}}` to sensors — no actual rule body. Sensors today cannot reconstruct rules from Horizon pushes.
- `PushRulesPayloadSchema` in Fleet API accepts a minimal rule shape that does not carry the Synapse match tree.

## Proposed model

Introduce a **catalog + overlay** split so tenant edits never shadow vendor catalog upgrades:

1. `SynapseRule` (new Prisma model) — immutable, versioned mirror of `production_rules.json`. Columns: `id` (u32), `description`, `risk`, `contributingScore`, `blocking`, `classification`, `state`, `versionSupport` (Json), `matches` (Json), `tags` (Json), `catalogVersion`, `catalogHash`, `importedAt`.
2. `TenantRuleOverride` (new) — per-tenant overlay: `tenantId`, `synapseRuleId`, `enabled`, `blockingOverride`, `sensitivityOverride`. Keeps catalog rows canonical.
3. Keep `CustomerRule` as-is for tenant-authored rules.
4. `RuleDistributor.pushRules()` assembles the push as `SynapseRule` ∪ `TenantRuleOverride` ∪ `CustomerRule`, sends full bodies keyed by `catalogHash + overrideHash` so sensors reconcile by hash, not count.

## Deliverables

- Prisma migration adding `SynapseRule` and `TenantRuleOverride`.
- `SynapseRuleLoader` service: reads `production_rules.json`, upserts catalog, records hash. Exposed as `horizon rules sync` CLI + startup job.
- Replace stub in `rule-distributor.ts:337-345` with real body assembly.
- Extend `PushRulesPayloadSchema` to carry the Synapse match-tree shape.
- `GET /api/v1/fleet/rules/available` — merged view (catalog + overrides + custom).
- `GET /api/v1/fleet/rules/catalog/version` — drift check for sensors/operators.
- Docs: short ADR under `docs/architecture` explaining catalog-vs-overlay split.

## Out of scope

- UI for editing overrides (follow-up task).
- Crucible rule sources (see task-75.11 federation boundary work).
- Migrating existing `CustomerRule` rows into the new model.

## Related

- TASK-45 (restore 237 production rules from archive) — predecessor; count has since grown to 248 per memory `project_waf_rule_count.md`.
- TASK-75 series (Horizon↔Apparatus federation) — aligns with aggregator direction.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 SynapseRule and TenantRuleOverride models exist in Prisma schema with a migration
- [ ] #2 SynapseRuleLoader imports all 248 rules from apps/synapse-pingora/src/production_rules.json into Horizon DB with a recorded catalogHash
- [ ] #3 GET /api/v1/fleet/rules/available returns the merged set (catalog + overrides + custom) for a tenant
- [ ] #4 RuleDistributor.pushRules sends full rule bodies (no placeholders) and the stub at rule-distributor.ts:337-345 is removed
- [ ] #5 PushRulesPayloadSchema validates the Synapse match-tree shape end-to-end
- [ ] #6 Sensor can receive a Horizon rule push, reconcile by hash, and apply rules identically to loading production_rules.json directly
- [ ] #7 ADR documenting catalog-vs-overlay split lands in docs/architecture
<!-- AC:END -->
