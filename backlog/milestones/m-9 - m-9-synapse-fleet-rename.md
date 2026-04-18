---
id: m-9
title: "m-9 synapse-fleet-rename"
---

## Description

Phase 3 of the Synapse brand consolidation: mechanical rename of Signal Horizon → Synapse Fleet across directory paths, published packages, internal code symbols, env vars, and user-facing documentation.

Decisions locked in (2026-04-18):
- Published packages: **clean cutover at major version bump**. No dual-publish, no deprecation aliases. Old `@atlascrew/horizon` and `nickcrew/horizon` stop publishing; new `@atlascrew/synapse-fleet` and `nickcrew/synapse-fleet` start at v1.0.0.
- Pingora `horizon/` module and `config.horizon*.yaml` filenames: **leave as-is** — handle in a later milestone. Internal abstraction, not user-visible.
- Env vars: **dual-accept** `HORIZON_*` and `SYNAPSE_FLEET_*` for a deprecation window; new name takes precedence; deprecation warning on old name.
- Archive + completed backlog entries: **leave untouched** — historical accuracy preserved.
- Directory rename: **single mechanical commit** (not split API/UI) to keep grep history intact.

Ordering is load-bearing: ADR lands first (fixes naming conventions), then directory rename (everything else depends on the new path), then the downstream workstreams can fan out in parallel.
