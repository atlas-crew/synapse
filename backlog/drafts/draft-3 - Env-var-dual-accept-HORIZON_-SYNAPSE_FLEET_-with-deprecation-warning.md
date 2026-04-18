---
id: DRAFT-3
title: 'Env var dual-accept: HORIZON_* + SYNAPSE_FLEET_* with deprecation warning'
status: Draft
assignee: []
created_date: '2026-04-18 11:08'
updated_date: '2026-04-18 11:30'
labels:
  - rename
  - brand-consolidation
  - backward-compat
  - config
milestone: m-9
dependencies:
  - TASK-87
  - TASK-88
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Per ADR-0003 decision C: accept both `HORIZON_*` and `SYNAPSE_FLEET_*` env vars for one major-version deprecation window. `SYNAPSE_FLEET_*` takes precedence when both are set. When `HORIZON_*` is read, emit a one-time deprecation warning on stderr naming the specific var and the replacement.

The removal-target version is fixed by ADR-0003 so it can't drift.

**Env vars confirmed in scope** (grep before rename):
- `HORIZON_URL` — hub URL for sensors
- `HORIZON_API_KEY` — sensor authentication
- Any other `HORIZON_*` that shows up in `apps/synapse-fleet/api/.env.example` or `.env.render.example` or pingora config-loading code
- CI/workflow env vars in `.github/workflows/*.yml`

**Implementation shape** (single-place helper):
```ts
function readEnv(canonical: string, legacy: string): string | undefined {
  const fromCanonical = process.env[canonical];
  const fromLegacy = process.env[legacy];
  if (fromCanonical !== undefined) return fromCanonical;
  if (fromLegacy !== undefined) {
    logger.warn(`Env var ${legacy} is deprecated; use ${canonical}. Removal scheduled for vX.Y.`);
    return fromLegacy;
  }
  return undefined;
}
```

Call that helper once per env read in `config.ts` so every deprecated-var read surfaces the warning and the removal version stays discoverable in one place.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Shared `readEnv(canonical, legacy)` helper landed in `apps/synapse-fleet/api/src/config.ts` (or equivalent) — single source of truth for the dual-accept behaviour
- [ ] #2 Every `process.env.HORIZON_*` read migrated to use the helper with the `SYNAPSE_FLEET_*` canonical name
- [ ] #3 Deprecation warning format is consistent: names the old var, names the new var, names the removal version. Fires once per var per process (not per read).
- [ ] #4 `.env.example` + `.env.render.example` updated to show the new canonical names as the primary form; the old names appear only in a migration note
- [ ] #5 Unit tests cover the three branches: canonical-only set, legacy-only set (warning fires), both set (canonical wins silently)
- [ ] #6 Pingora-side env vars scoped out — that's deferred per ADR-0003 decision E
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deprioritized 2026-04-18 per user direction: env var compat is only needed if we rename the env vars, which is internal scope we're not touching yet. Revisit if/when we do a second rename phase.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Operational docs (deployment, self-hosted-standalone guides) updated to show the new env var names as the primary form, with a short migration note for operators on the old names
- [ ] #2 Changelog entry drafted with migration steps for existing deployments
<!-- DOD:END -->
