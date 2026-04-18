---
id: TASK-87
title: 'ADR-0003: package + published-docs rename — Signal Horizon → Synapse Fleet'
status: Done
assignee: []
created_date: '2026-04-18 11:08'
updated_date: '2026-04-18 11:46'
labels:
  - adr
  - architecture
  - rename
  - brand-consolidation
milestone: m-9
dependencies: []
references:
  - apps/signal-horizon/docs/architecture/adr-0001-synapse-catalog-overlay.md
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Document the narrow Phase 3 of the Synapse brand consolidation: rename only user-facing published surfaces (npm + Docker packages, GitHub Pages content), leave internal repo paths and code symbols on "horizon" for now.

This ADR exists because the split itself — "external names become Synapse Fleet, internal identifiers stay horizon until later" — is a decision worth capturing explicitly. Without it, a future contributor will see the inconsistency (repo dir says `signal-horizon/`, package says `synapse-fleet`) and either try to "clean it up" prematurely or assume the rename was abandoned mid-flight.

Decisions (locked 2026-04-18):

**A. Package rename — clean cutover at major version bump.**
- Stop publishing `@atlascrew/horizon` and `nickcrew/horizon`.
- Start publishing `@atlascrew/synapse-fleet` and `nickcrew/synapse-fleet` at v1.0.0.
- No dual-publish, no deprecation aliases.
- Release notes must explicitly call out the rename for existing `docker pull` / `npm install` users.

**B. Published documentation — full rewrite.**
- README.md, site/ (VitePress → GitHub Pages), dockerhub READMEs, npm package READMEs all show "Synapse Fleet" as the product name.
- Historical ADRs (0001, 0002) and archived/completed backlog entries keep their original "Horizon" text for historical accuracy.

**C. Internal scope stays on "horizon" for now (explicitly deferred):**
- Directory `apps/signal-horizon/` — not renamed.
- Code symbols (`HorizonClient`, `horizonStore`, `SignalHorizonPageWrapper`) — not renamed.
- Env vars (`HORIZON_URL`, `HORIZON_API_KEY`) — not renamed; no compat layer needed since names aren't changing.
- Pingora `horizon/` module — not renamed (was already deferred).
- Acceptable temporary inconsistency: repo path says `signal-horizon/` while the package it publishes is `synapse-fleet`. Documented here so future readers see it's intentional.

**D. Release sequencing.**
- Package rename (TASK-89) can land without a dir rename — the `package.json:name` field and the publish workflow are independent of file paths.
- Docs rewrite (TASK-92) references the new package names from TASK-89 but not any directory changes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ADR written at `apps/signal-horizon/docs/architecture/adr-0003-synapse-fleet-rename.md` following the format of adr-0001 and adr-0002, with status=Proposed initially
- [x] #2 Decision section covers the 4 lettered boundaries (A–D) above with the locked-in choices stated unambiguously
- [x] #3 Naming table published: new canonical names for published packages (`@atlascrew/synapse-fleet`, `nickcrew/synapse-fleet`) and any renamed doc pages. Internal paths and symbols explicitly listed as 'unchanged — see decision C'.
- [x] #4 Rejected alternatives section documents why clean cutover (not dual-publish) and why internal rename is deferred
- [x] #5 Acceptable-inconsistency section explicit: repo path says `apps/signal-horizon/` while the published package name is `@atlascrew/synapse-fleet`. Future contributors see this is intentional, not mid-flight.
- [x] #6 ADR moves to status=Accepted after stakeholder sign-off; TASK-89 and TASK-92 unblock from there
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

ADR-0003 drafted, reviewed, and accepted. Documents the narrow Phase 3 of the Synapse brand consolidation: rename only user-facing published surfaces (npm + Docker packages, GitHub Pages content), leave internal repo paths and code symbols on "horizon" for now.

## Key decisions locked

- **A. Package rename — clean cutover at major version bump.** No dual-publish, no deprecation aliases. Old packages stop receiving updates at the last v1.x; new packages start at v1.0.0.
- **B. Published documentation — full rewrite to "Synapse Fleet."** Historical ADRs and archived backlog stay on "Horizon" for historical accuracy.
- **C. Internal scope — deferred.** Repo directory, code symbols, env vars, pingora `horizon/` module all keep their current names. The inconsistency (repo path `apps/signal-horizon/` ships package `@atlascrew/synapse-fleet`) is intentional, documented, and scheduled for resolution via parked drafts DRAFT-1/2/3.
- **D. Release sequencing.** TASK-89 (package rename) ships independently; TASK-92 (docs) follows.

## Deliverable

- `apps/signal-horizon/docs/architecture/adr-0003-synapse-fleet-rename.md` — full ADR with Context, Decision, Consequences (including the "Acceptable inconsistency" section), Rejected alternatives, and References.
- Naming table in the ADR serves as single source of truth for TASK-89 and TASK-92.

## Followups

- DoD #2 (release-notes template update) rolls into TASK-89 since the release-notes text is part of the package cutover artifact.
- When the internal rename eventually ships (DRAFT-1/2/3), this ADR should be superseded rather than silently outdated — it documents a transitional state, not a stable architecture.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Downstream rename tasks link back to ADR-0003 as their source of truth for canonical names
- [ ] #2 Release-notes template updated with the package-rename cutover guidance (`@atlascrew/horizon` users must install `@atlascrew/synapse-fleet`)
<!-- DOD:END -->
