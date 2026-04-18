---
id: DRAFT-1
title: Rename apps/signal-horizon/ → apps/synapse-fleet/ (single mechanical commit)
status: Draft
assignee: []
created_date: '2026-04-18 11:08'
updated_date: '2026-04-18 11:30'
labels:
  - rename
  - brand-consolidation
  - mechanical
milestone: m-9
dependencies:
  - TASK-87
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rename the workspace directory `apps/signal-horizon/` → `apps/synapse-fleet/` in a single commit, per ADR-0003 decision B. All downstream rename work (packages, env vars, docs) depends on the new path.

Single-commit requirement is deliberate: keeps `git log --follow` working across the move, keeps the bisect history intact, and avoids a transient broken state where half the repo references the old path. Accept the big diff in exchange for history cleanliness.

Scope is path-only. Symbol renames (`HorizonClient` etc), package name in package.json fields, and docs prose are out of scope here — they're separate tasks under the same milestone.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Directory moved via `git mv apps/signal-horizon apps/synapse-fleet` (preserves git history)
- [ ] #2 All import paths across the monorepo updated from `apps/signal-horizon/` to `apps/synapse-fleet/` — TypeScript imports, pnpm-workspace.yaml glob, justfile targets, Dockerfile COPY paths, render.yaml services, Nx project.json files
- [ ] #3 GitHub workflow files renamed: `.github/workflows/signal-horizon-quality.yml` → `synapse-fleet-quality.yml`; `.github/workflows/signal-horizon-preflight.yml` → `synapse-fleet-preflight.yml`. Update any `paths:` filter patterns in those workflows and others (publish-docker, publish-npm) that trigger on the old path.
- [ ] #4 `nginx/signal-horizon.conf` → `nginx/synapse-fleet.conf`; `systemd/signal-horizon.service` → `systemd/synapse-fleet.service`. Update the `Caddyfile` reference and any systemd unit paths.
- [ ] #5 `pnpm install` succeeds after the rename; `pnpm build` + typecheck pass across the renamed workspace
- [ ] #6 All existing tests in the renamed workspace pass (api, ui, shared)
- [ ] #7 CI workflows dispatched on the rename PR pass green before merge
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deprioritized 2026-04-18 per user direction: only published-packages and published-docs are in scope for m-9 near-term. Directory rename remains a future task but is NOT a prerequisite for TASK-89 or TASK-92 anymore.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 PR description calls out the size explicitly and links to ADR-0003 so reviewers know this is a mechanical rename, not feature work
- [ ] #2 Coordinate merge with active feature branches — a parallel agent's dirty edits to `apps/signal-horizon/api/src/api/routes/fleet.ts` etc. must land or be rebased before this merges; otherwise conflict hell
- [ ] #3 Post-merge: update developer onboarding docs + local setup notes that cd into the renamed directory
<!-- DOD:END -->
