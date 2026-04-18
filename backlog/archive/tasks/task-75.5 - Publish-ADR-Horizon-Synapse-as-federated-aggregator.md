---
id: TASK-75.5
title: 'Publish ADR: Horizon/Synapse as federated aggregator'
status: To Do
assignee: []
created_date: '2026-04-17 03:41'
updated_date: '2026-04-18 05:45'
labels:
  - architecture
  - adr
  - documentation
  - federation
milestone: m-7
dependencies: []
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Write and publish an Architecture Decision Record capturing the federation pattern: Synapse/Horizon is the read-side aggregator across standalone sub-products (Apparatus, Crucible). Sub-products own their write-side management UI and ship independently.

ADR sections:
- Context: standalone sub-products, brand consolidation to Synapse, existing Active Defense duplication in Horizon.
- Decision: federated read-side aggregator; write-side lives in sub-product UI; versioned contracts.
- Alternatives considered: full consolidation (rejected — couples release cycles, hard-depends Horizon for standalone deployments); no aggregation (rejected — scatters operator experience, weakens Synapse brand story).
- Consequences: Horizon must stay thin on write-side; contract drift risk shifted to API versioning layer; deep-link UX requires SSO coordination.
- Migration notes: reference the Active Defense demotion tasks; pattern applies to Crucible next.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/architecture/adrs/0XXX-horizon-as-federated-aggregator.md committed (number assigned per existing ADR sequence)
- [ ] #2 Alternatives section lists at least 'full consolidation' and 'no aggregation' with explicit rejection reasons
- [ ] #3 Federation pattern documents read-side-only boundary, deep-link conventions, and API contract versioning strategy
- [ ] #4 ADR linked from docs/NAVIGATOR.md under architecture section
- [ ] #5 Links to parent TASK-75 and the Active Defense demotion plan for migration traceability
<!-- AC:END -->
