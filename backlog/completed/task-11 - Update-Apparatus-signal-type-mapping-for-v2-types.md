---
id: TASK-11
title: Update Apparatus signal type mapping for v2 types
status: Done
assignee: []
created_date: '2026-04-03 18:29'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - signals
  - adapter
milestone: m-0
dependencies:
  - TASK-9
references:
  - apps/synapse-pingora/src/signals/adapter.rs
  - libs/client/src/types.ts (Apparatus repo)
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The current Cutlass Protocol v1.0.0 adapter in `synapse-pingora/src/signals/adapter.rs` maps only 4 signal types (honeypot_hit, trap_trigger, protocol_probe, dlp_match). Apparatus now emits richer event types via SSE:

- `deception` events (honeypot hits, shell commands, SQLi probes)
- `tarpit` events (IP trapped/released)
- `threat-intel` events (coordinated attack detection)
- `request` events (general traffic)
- `health` events

Update the adapter to handle the new event shapes from apparatus-lib types. This can be done in the Horizon API (TypeScript) rather than Synapse (Rust), since the new integration flows through the API server directly.

Create `apps/signal-horizon/api/src/services/apparatusSignalAdapter.ts` that maps apparatus-lib event types to Horizon's internal signal model.
<!-- SECTION:DESCRIPTION:END -->
