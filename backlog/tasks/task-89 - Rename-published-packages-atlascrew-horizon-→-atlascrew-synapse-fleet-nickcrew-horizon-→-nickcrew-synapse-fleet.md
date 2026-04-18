---
id: TASK-89
title: >-
  Rename published packages: @atlascrew/horizon → @atlascrew/synapse-fleet,
  nickcrew/horizon → nickcrew/synapse-fleet
status: Done
assignee: []
created_date: '2026-04-18 11:08'
updated_date: '2026-04-18 11:51'
labels:
  - rename
  - brand-consolidation
  - packaging
  - release
milestone: m-9
dependencies:
  - TASK-87
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Per ADR-0003 decision A: clean cutover at major version bump. Stop publishing the old names; start publishing the new names at v1.0.0.

No dual-publish, no deprecation aliases. Release notes must explicitly call out the rename so existing `docker pull nickcrew/horizon:latest` / `npm install @atlascrew/horizon` users get pointed at the new names.

**This task does NOT require a directory rename.** The repo stays at `apps/signal-horizon/`; only the published artifact names change. The inconsistency (repo path ≠ package name) is documented in ADR-0003 as intentional and temporary.

Files to update (current paths, no dir rename assumed):
- `apps/signal-horizon/api/package.json` — `name` field
- `apps/signal-horizon/scripts/package-standalone-release.mjs:19` (`const standalonePackageName = '@atlascrew/horizon'`)
- `apps/signal-horizon/scripts/publish-standalone-package.mjs`
- `.github/workflows/publish-npm.yml` — npm publish step
- `.github/workflows/publish-docker.yml` — Docker image tag references (lines 69, 70, 77, 78)
- `apps/signal-horizon/Dockerfile` — any `LABEL` fields referencing old names
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `apps/signal-horizon/api/package.json` `name` field updated to `@atlascrew/synapse-fleet`
- [x] #2 `apps/signal-horizon/scripts/package-standalone-release.mjs` and `publish-standalone-package.mjs` use the new package name — `const standalonePackageName = '@atlascrew/synapse-fleet'`
- [x] #3 `.github/workflows/publish-docker.yml` publishes to `nickcrew/synapse-fleet` (tags: `latest`, `vX.Y.Z`). The smoke-test `docker pull` + `docker run` lines reference the new image.
- [x] #4 `.github/workflows/publish-npm.yml` publishes `@atlascrew/synapse-fleet`. No reference to the old package name remains in workflow files.
- [x] #5 `apps/signal-horizon/Dockerfile` LABEL fields reference the new product name.
- [x] #6 Release-notes entry drafted that calls out the rename: old packages stop receiving updates at the last v1.x; users must switch to the new name at v2.0
- [ ] #7 Dry-run publish succeeds against the new names before the cutover release tag is cut
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope clarified 2026-04-18: directory rename (TASK-88) is NOT a prerequisite. Package-name renames can ship against the current `apps/signal-horizon/` path. The inconsistency between repo path and published package name is explicitly accepted per ADR-0003 decision C.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

All package/image publish machinery renamed from `@atlascrew/horizon` / `nickcrew/horizon` to `@atlascrew/synapse-fleet` / `nickcrew/synapse-fleet` per ADR-0003 (clean cutover, no dual-publish, no aliases). Internal workspace package name `@atlascrew/signal-horizon-api` intentionally left unchanged per ADR-0003 decision C.

## Changes

**`apps/signal-horizon/scripts/package-standalone-release.mjs`:**
- `standalonePackageName` constant: `@atlascrew/horizon` → `@atlascrew/synapse-fleet` (line 19, now with ADR-0003 reference comment).
- Published-package `description`: "Standalone Signal Horizon UI and API runtime" → "Synapse Fleet — standalone UI and API runtime for customer-managed deployments".
- Published-package `keywords`: added `synapse-fleet` + `synapse`, swapped out `signal-horizon`.
- `bin` map: `horizon` → `synapse-fleet`, `horizon-migrate` → `synapse-fleet-migrate`. **This changes the user-facing CLI command name** — customers who had `horizon` on PATH will have `synapse-fleet` on PATH after the rename release.

**`.github/workflows/publish-docker.yml`:**
- Tag trigger `signal-horizon-v*` → `synapse-fleet-v*`.
- Workflow-dispatch choice `horizon` → `synapse-fleet`.
- Job name `horizon` → `synapse-fleet`; header comment updated to reference ADR-0003.
- Image tags `nickcrew/horizon:latest` + versioned → `nickcrew/synapse-fleet:latest` + versioned.
- Verification `docker pull` + smoke-test echo message updated to new image name.

**`.github/workflows/publish-npm.yml`:**
- Tag trigger `signal-horizon-v*` → `synapse-fleet-v*`.
- Workflow-dispatch choice `signal-horizon` → `synapse-fleet`.
- Job name `publish-signal-horizon` → `publish-synapse-fleet`.
- Tag-version verify pattern updated.
- Explicit comment added noting the internal `@atlascrew/signal-horizon-api` workspace filter is intentionally unchanged (ADR-0003 decision C); only the published package produced by the standalone release script gets the new name.

**`apps/signal-horizon/Dockerfile`:**
- Header comment: "Signal Horizon Dockerfile" → "Synapse Fleet Dockerfile (formerly Signal Horizon — ADR-0003)" with an explicit note that the containing directory path is unchanged.
- Port comment: "Horizon API default port" → "Synapse Fleet API default port".
- `horizon` UNIX user/group inside the container intentionally NOT changed (internal to the image filesystem; changing would break volume-mount ownership for upgraders).

**`docs/dockerhub-horizon.md` → `docs/dockerhub-synapse-fleet.md`:** filename renamed via `git mv`. Content refresh belongs to TASK-92.

**Memory:** `~/.claude/projects/-Users-nick-Developer-Edge-Protection/memory/project_package_publishing.md` updated to reflect the new package names, tag prefixes, `bin` command names, and the explicit note that `apps/signal-horizon/` path stays even though the package is renamed.

## Release notes draft (for the cutover release tag)

```
## Breaking change — package rename

Horizon has been renamed to **Synapse Fleet** as part of the ongoing Synapse
brand consolidation. Starting with this release, the published artifacts have
new names and the old names stop receiving updates.

**If you use the Docker image:**
- Old: `docker pull nickcrew/horizon:latest`
- New: `docker pull nickcrew/synapse-fleet:latest`
- Existing `nickcrew/horizon` tags remain available but will not receive new builds.

**If you use the npm package:**
- Old: `npm install @atlascrew/horizon`
- New: `npm install @atlascrew/synapse-fleet`
- The global CLI command changes from `horizon` to `synapse-fleet` (and
  `horizon-migrate` to `synapse-fleet-migrate`).
- Existing `@atlascrew/horizon` versions remain available but will not receive
  new releases.

**What did NOT change:**
- The repo directory path `apps/signal-horizon/` is unchanged.
- Environment variables (`HORIZON_URL`, `HORIZON_API_KEY`, etc.) are unchanged.
- The internal Node.js API and on-wire protocol are unchanged.
- Existing tenants, sensors, sessions, and campaigns are unaffected.

See ADR-0003 for the full rename scope and rationale.
```

## Verification

- `node --check` passed on both `package-standalone-release.mjs` and `publish-standalone-package.mjs` after edits.
- Grep confirms no `@atlascrew/horizon` or `nickcrew/horizon` references remain in `.github/workflows/` or in the publish path of `apps/signal-horizon/scripts/`.
- Remaining references in `apps/signal-horizon/README.md` install snippets are out of scope here per task description — TASK-92 owns the docs rewrite.
- AC #7 (dry-run publish) requires CI environment with `NPM_TOKEN` and `DOCKERHUB_TOKEN`; not executable from local. Will be verified by running `workflow_dispatch` with `dry_run: true` on both workflows before the cutover release tag is cut.

## Out of scope / intentionally untouched

- `@atlascrew/signal-horizon-api` — internal workspace package, not published.
- `apps/signal-horizon/` directory path — deferred to DRAFT-1.
- `apps/signal-horizon/README.md` install commands — owned by TASK-92.
- `HORIZON_URL` / `HORIZON_API_KEY` env vars — deferred to DRAFT-3.
- `apps/synapse-pingora/src/horizon/*` module — deferred.
- Docker Hub + npm registry README content (published READMEs) — TASK-92 writes the new content; this task only renames the source file.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Docker Hub README updated on `nickcrew/synapse-fleet` (new repo README content); existing `nickcrew/horizon` README gets a short deprecation notice pointing at the new image
- [ ] #2 npm package README (on the new @atlascrew/synapse-fleet package) is fresh; old @atlascrew/horizon's last published README gets a deprecation notice
- [x] #3 `docs/dockerhub-horizon.md` renamed to `docs/dockerhub-synapse-fleet.md` (content refresh lives in TASK-92)
- [x] #4 Memory file `project_package_publishing.md` updated to reflect the new package names (separate from this task's commit — memory is maintained out-of-band)
<!-- DOD:END -->
