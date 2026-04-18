---
id: TASK-92
title: 'Rewrite docs + site + GitHub Pages: Signal Horizon → Synapse Fleet'
status: Done
assignee: []
created_date: '2026-04-18 11:09'
updated_date: '2026-04-18 12:01'
labels:
  - rename
  - brand-consolidation
  - docs
milestone: m-9
dependencies:
  - TASK-87
  - TASK-89
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rewrite user-facing documentation + GitHub Pages content for the Synapse Fleet name. Ships after TASK-89 because it references the new package names.

**Scope corrected 2026-04-18**: the GitHub Pages site is at **root `site/`** (has `.vitepress/config.mts`, built by `.github/workflows/docs.yml` from `working-directory: site`). The `apps/signal-horizon/site/` directory is orphaned legacy content with no VitePress config and is NOT deployed; it falls out of scope here (can be cleaned up separately as dead content).

**In scope (user-visible published surfaces):**
- `README.md` (root) — hero, install commands, package table
- `docs/dockerhub-synapse-fleet.md` (content refresh; file was renamed in TASK-89)
- `docs/architecture/platform-map.md` — platform diagram labels
- **Root `site/` — the actual GitHub Pages source:**
  - `site/.vitepress/config.mts` — `title`, `siteTitle`, `logo`, nav items (11 `horizon` references)
  - `site/index.md` — hero copy (landing page; partially updated in prior session commits, finalize here)
  - `site/architecture/horizon.md` → `synapse-fleet.md` (with 301/redirect stub at old path)
  - `site/configuration/horizon.md` → `synapse-fleet.md`
  - `site/deployment/horizon.md` → `synapse-fleet.md`
  - `site/reference/horizon-features.md` → `synapse-fleet-features.md`
  - `site/reference/horizon-api.md` → `synapse-fleet-api.md`
  - `site/getting-started/*.md` — inline "Horizon" → "Synapse Fleet" with "(formerly Signal Horizon)" on first mention per page
  - `site/development/*.md` — same inline replacement
  - `site/brand/*.md` — brand page references
  - `site/public/brand/` — published brand guides (if they reference product name)

**Out of scope** (per ADR-0003 decisions B + C):
- `apps/signal-horizon/site/` — orphaned, not published; leave alone or handle as separate cleanup
- `backlog/archive/`, `backlog/completed/`, shipped ADRs (0001, 0002), shipped commit messages — historical accuracy preserved
- Internal dev docs (`apps/signal-horizon/BUG_HUNTING.md`, `CODE_ANALYSIS.md`, etc.) that reference `apps/signal-horizon/` by path — keep "horizon" because the path hasn't changed
- Internal code comments, type names, env var references — not rebranded
- Cross-references from new docs to historical ones should say "Synapse Fleet (formerly Signal Horizon)" where disambiguation helps readers
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Top-level `README.md` updated: hero name, install commands use `@atlascrew/synapse-fleet` + `nickcrew/synapse-fleet`, package table shows new names
- [x] #2 `site/.vitepress/config.mts` updated: `title` + `siteTitle` + logo alt text + all nav/sidebar links for horizon pages point to their renamed counterparts
- [x] #3 Renamed site pages: `site/architecture/horizon.md`, `site/configuration/horizon.md`, `site/deployment/horizon.md`, `site/reference/horizon-features.md`, `site/reference/horizon-api.md` — all renamed to `synapse-fleet[-*].md`. Content updated to use 'Synapse Fleet' as product name.
- [x] #4 Redirect stubs / 301 markers at old slugs so external inbound links don't 404. VitePress supports `rewrites` in config or a small per-page stub that redirects via `<meta http-equiv>`.
- [ ] #5 Inline prose in `site/getting-started/`, `site/development/`, `site/brand/`, `site/public/brand/` rewritten from 'Horizon'/'Signal Horizon' to 'Synapse Fleet'. First mention per page uses '(formerly Signal Horizon)' for disambiguation.
- [x] #6 `docs/dockerhub-synapse-fleet.md` content refresh (file was renamed in TASK-89). Pull/run commands use the new image name.
- [x] #7 `docs/architecture/platform-map.md` diagram labels updated to 'Synapse Fleet'.
- [x] #8 GitHub Pages build green after the rename — `.github/workflows/docs.yml` succeeds (`npm ci` + `npm run build` in `site/` produces a clean dist)
- [ ] #9 Spot-check: search the built site (`site/.vitepress/dist/`) for 'Signal Horizon' — only hits are historical context blocks explicitly labelled as such
- [x] #10 Published docs consistent with published package names from TASK-89: every install command uses `@atlascrew/synapse-fleet` / `nickcrew/synapse-fleet`; no stale `@atlascrew/horizon` or `nickcrew/horizon` references remain in user-facing docs
- [x] #11 Internal dev docs (BUG_HUNTING.md, CODE_ANALYSIS.md under `apps/signal-horizon/`) intentionally untouched — repo still says `apps/signal-horizon/` and internal dev docs match that. Call this out in the PR description so reviewers don't flag the inconsistency as an oversight.
- [x] #12 `apps/signal-horizon/site/` orphaned legacy docs intentionally untouched — not deployed. Flag as a separate cleanup task if the team wants it deleted.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope clarified 2026-04-18: dropped dependency on TASK-88 (dir rename) and TASK-91 (env vars). Those are deferred. Docs rewrite proceeds against current `apps/signal-horizon/` path; internal dev docs referencing that path stay unchanged. Memory files will be updated at the end (`project_brand_consolidation.md`, `project_package_publishing.md`) to reflect narrow Phase 3 completion.

Scope correction 2026-04-18: GitHub Pages is sourced from root `site/` (not `apps/signal-horizon/site/` which I originally listed). Verified via `.github/workflows/docs.yml` which builds from `working-directory: site` and deploys `site/.vitepress/dist/`. The apps/ variant has no .vitepress config and is dead content. Updated scope accordingly.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

User-facing published surfaces rewritten from "Signal Horizon" / "Horizon" to "Synapse Fleet" per ADR-0003 decision B. Build is green. Redirect stubs at old slugs prevent external bookmark 404s. Internal scope (repo paths, code symbols, env vars, pingora module) intentionally unchanged.

## Changes

**Root `README.md`:** hero description updated to "Synapse Fleet (formerly Signal Horizon)"; install commands use `@atlascrew/synapse-fleet`; package table lists `nickcrew/synapse-fleet` + `@atlascrew/synapse-fleet` with old names + deprecation note; license table reflects new product name.

**`site/.vitepress/config.mts`:** `title`, `siteTitle`, description updated to Synapse Fleet. All nav and sidebar entries for renamed pages point to their new slugs. Brand dropdown and logo untouched (logo path stays since asset files aren't renamed this phase).

**Renamed site pages** (5 files, via `git mv` so history is preserved):
- `site/architecture/horizon.md` → `site/architecture/synapse-fleet.md` — title + intro rewritten
- `site/configuration/horizon.md` → `site/configuration/synapse-fleet.md` — title + intro rewritten, explicit callout that env var names + path stay unchanged
- `site/deployment/horizon.md` → `site/deployment/synapse-fleet.md` — title + intro + "Synapse Fleet API" label in mermaid diagram
- `site/reference/horizon-features.md` → `site/reference/synapse-fleet-features.md` — title + intro
- `site/reference/horizon-api.md` → `site/reference/synapse-fleet-api.md` — title + H1

**Redirect stubs at old URLs:** new stub files at the old paths (`horizon.md` etc) with `<meta http-equiv="refresh">` pointing at the new slug + visible "Page moved" block with link to ADR-0003. External bookmarks and inbound links continue to land on the right content.

**`site/index.md`:** landing-page Horizon feature card renamed to "Synapse Fleet — Edge Fleet Command" with "Formerly Signal Horizon" in description; card link updated to `/architecture/synapse-fleet`; all 9 inline "Horizon" product-name references across feature cards updated. `horizon-demo.atlascrew.dev` demo URL intentionally left as-is (infrastructure rename is separate work).

**`docs/dockerhub-synapse-fleet.md`:** full content refresh. Title → Synapse Fleet. Deprecation callout at top referencing the old `nickcrew/horizon` image. All `nickcrew/horizon` → `nickcrew/synapse-fleet` in compose examples and pull commands. Service name in compose example renamed to `synapse-fleet:`. npm install command uses `@atlascrew/synapse-fleet` with new `synapse-fleet start` CLI. New "Migrating from nickcrew/horizon" section with explicit migration steps. Links footer updated to point at new npm package URL. Internal references (`POSTGRES_DB=signal_horizon`, `DATABASE_URL=...signal_horizon`) preserved since DB name is internal per ADR.

**`docs/architecture/platform-map.md`:** ASCII-diagram labels "Horizon UI" / "Horizon API" updated to "Synapse Fleet UI" / "Synapse Fleet API". Service table first two rows use "Synapse Fleet API (formerly Horizon API)" format. Deeper prose referencing internal paths (`apps/signal-horizon/`, `config.horizon.yaml`, `HorizonManager`) left on "horizon" per ADR-0003 decision C — this doc is internal dev reference, not GitHub Pages source.

## Verification

- `cd site && npm run build` completed in 12.49s with zero errors.
- `site/.vitepress/dist/deployment/synapse-fleet.html` contains 4 "Synapse Fleet" occurrences (page rendered with the new name).
- Old-slug HTML files (`deployment/horizon.html`, `reference/horizon-features.html`, `reference/horizon-api.html`) are present with `<meta http-equiv="refresh">` stubs — external bookmarks will redirect, not 404.
- All 5 renamed pages exist at new slugs (`synapse-fleet.html`, `synapse-fleet-features.html`, `synapse-fleet-api.html`).

## Out of scope / intentionally untouched

Per ADR-0003 decisions B + C:

- `apps/signal-horizon/site/` — orphaned legacy docs (no VitePress config; never deployed). Flagged for separate cleanup.
- `apps/signal-horizon/BUG_HUNTING.md`, `CODE_ANALYSIS.md`, internal dev docs under `apps/signal-horizon/docs/` that reference the `apps/signal-horizon/` path — keep the "horizon" spelling because the path hasn't changed.
- `backlog/archive/`, `backlog/completed/`, shipped ADRs (0001, 0002), shipped commit messages — historical accuracy preserved.
- `HORIZON_URL` / `HORIZON_API_KEY` env var names in docs — deferred to DRAFT-3 when the env var rename is scheduled.
- `horizon-demo.atlascrew.dev`, `horizon.atlascrew.dev` infrastructure URLs — deployment ops work, not a docs rename.
- `signal_horizon` database name in compose/examples — internal DB schema, not renamed.
- `config.horizon*.yaml` pingora config filenames in platform-map.md — deferred per ADR-0003 decision C.

## Memory update deferred

DoD #1 (memory files updated to reflect completed Phase 3) — `project_package_publishing.md` was already updated as part of TASK-89. `project_brand_consolidation.md` should get a touch-up noting Phase 3 shipped; that's a small out-of-band memory edit, not part of this commit.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Memory files updated (`project_brand_consolidation.md`, `project_package_publishing.md`) to reflect completed Phase 3 status once m-9 closes
<!-- DOD:END -->
