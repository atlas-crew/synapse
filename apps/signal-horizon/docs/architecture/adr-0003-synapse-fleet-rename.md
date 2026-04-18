# ADR 0003 — Signal Horizon → Synapse Fleet: narrow rename of published surfaces

- **Status:** Accepted
- **Date:** 2026-04-18
- **Related:** TASK-87 (this ADR), TASK-89 (package rename), TASK-92 (docs rewrite), ADR-0001 (catalog overlay), ADR-0002 (fleet-view strategy), memory `project_brand_consolidation.md`, memory `project_package_publishing.md`

## Context

The project is mid-rollout of a brand consolidation that collapses the stack (WAF sensor, hub, supporting tools) under a single "Synapse" umbrella, with each sub-product taking a "Synapse {name}" form. Phases 1 and 2 — admin console palette resync and UI sidebar wordmark change to "Synapse Fleet" — have already shipped. Phase 3 is the mechanical rename of the hub product formerly known as "Signal Horizon" (or "Horizon") to "Synapse Fleet."

The temptation is to treat Phase 3 as a single sweeping rename: directory path, every code symbol, every env var, every comment, every doc, every published artifact — all at once. A grep for `horizon` across the repo returns ~1,090 matches across ~250 files. Attempting that in one PR produces a merge conflict with every active feature branch and a bisect wasteland for anyone debugging production after the cut.

The alternative is to be disciplined about what "the rename" actually means for users vs. for contributors. A customer running `docker pull nickcrew/horizon:latest` against production interacts with one surface — the published package name. A contributor cloning the repo and running `cd apps/signal-horizon/api && pnpm dev` interacts with a completely different surface — the repo layout. These are not the same surface, do not need to change on the same timeline, and in fact changing them together is what creates the merge-conflict risk.

This ADR scopes Phase 3 down to only the *user-visible* surfaces:

- **What users pull:** npm packages, Docker images.
- **What users read:** README, published documentation (GitHub Pages), package registry README content.

And explicitly defers:

- **What contributors see in the repo:** directory paths, code symbols, env var names, internal dev docs, the pingora `horizon/` module.

The cost is a documented inconsistency during the deferral window: the repo directory says `apps/signal-horizon/` while the package it ships is `@atlascrew/synapse-fleet`. The value is that external artifacts can rebrand on their own schedule — faster than a cross-cutting internal rename would allow — without holding up every in-flight internal branch.

## Decision

### A. Package rename — clean cutover at major version bump

- `@atlascrew/horizon` (npm) and `nickcrew/horizon` (Docker Hub) **stop** publishing at the next major release.
- `@atlascrew/synapse-fleet` and `nickcrew/synapse-fleet` **start** publishing at `v1.0.0`.
- **No dual-publish.** No deprecation aliases on the npm side. No additional image tags on the Docker side.
- Release notes accompanying the cutover release must name both old and new packages and give `npm install` / `docker pull` migration commands.
- The last `v1.x` builds of the old packages remain available on the registries for users who can't migrate immediately, but will not receive updates.

### B. Published documentation — full rewrite to "Synapse Fleet"

- Top-level `README.md`, workspace `apps/signal-horizon/README.md`, the VitePress site under `apps/signal-horizon/site/`, and the Docker Hub + npm registry READMEs all reference **Synapse Fleet** as the product name.
- Doc pages named after the old product are renamed: `docs/dockerhub-horizon.md` → `docs/dockerhub-synapse-fleet.md`; `site/deployment/horizon.md` → `site/deployment/synapse-fleet.md`; `site/reference/horizon-*.md` → `site/reference/synapse-fleet-*.md`.
- Old URLs get 301 / redirect stubs so external links don't 404.
- Shipped ADRs (0001, 0002), committed code comments, and archived or completed backlog entries retain their original "Horizon" text. Rewriting them would make the historical record lie about what the product was called when those decisions were made. Cross-references from new documents to historical ones disambiguate with the form **"Synapse Fleet (formerly Signal Horizon)"** where clarity helps the reader.

### C. Internal scope — deferred, intentionally

Every one of these keeps the "horizon" spelling under the current ADR:

- **Repo directory** — `apps/signal-horizon/` stays. Not renamed.
- **Code symbols** — `HorizonClient`, `horizonStore`, `SignalHorizonPageWrapper`, and every other "Horizon" identifier in TypeScript / Rust source. Not renamed.
- **Environment variables** — `HORIZON_URL`, `HORIZON_API_KEY`, etc. Not renamed. No compat layer required because nothing is changing.
- **Pingora `horizon/` module** (`apps/synapse-pingora/src/horizon/*`) — not renamed. The abstraction name ("the far side of the tunnel") is arguably brand-agnostic and renaming it prematurely welds it to a specific product name.
- **Internal dev docs** — `BUG_HUNTING.md`, `CODE_ANALYSIS.md`, architecture notes under `apps/signal-horizon/docs/` that reference repo paths — stay on "horizon" because the paths they reference haven't changed.
- **Historical backlog** — `backlog/archive/` and `backlog/completed/` not touched.

The parked tasks DRAFT-1 (directory rename), DRAFT-2 (code symbols), and DRAFT-3 (env var dual-accept) exist as already-scoped work for when this internal rename gets picked up. They are not scheduled.

### D. Release sequencing

- **TASK-89 (package rename)** ships independently of any directory work. `package.json:name` is a string that the publish workflow reads; it does not depend on the containing directory path. The workflow files in `.github/workflows/publish-*.yml` get updated in the same PR that flips the names.
- **TASK-92 (docs rewrite)** depends on TASK-89 because every install command in the docs needs to reference the new package names. Sequenced after the cutover release has the new packages published.
- Customer-visible cutover point: the release tag that bumps the major version and flips the publish target. Until that tag, users keep seeing `@atlascrew/horizon` + `nickcrew/horizon`. After that tag, only the new names get new builds.

### Naming table

| Surface | Old | New | Changes in m-9? |
|---|---|---|---|
| npm package (hub server) | `@atlascrew/horizon` | `@atlascrew/synapse-fleet` | **Yes** — TASK-89 |
| Docker image (hub server) | `nickcrew/horizon` | `nickcrew/synapse-fleet` | **Yes** — TASK-89 |
| Published product name (all docs) | "Signal Horizon" / "Horizon" | "Synapse Fleet" | **Yes** — TASK-92 |
| GitHub Pages page filenames | `dockerhub-horizon.md`, `horizon-features.md`, `horizon-api.md`, `deployment/horizon.md` | `dockerhub-synapse-fleet.md`, `synapse-fleet-features.md`, `synapse-fleet-api.md`, `deployment/synapse-fleet.md` | **Yes** — TASK-92 |
| Repo directory | `apps/signal-horizon/` | `apps/signal-horizon/` | No — deferred (DRAFT-1) |
| Code symbols | `HorizonClient`, `horizonStore`, `SignalHorizonPageWrapper`, `signalHorizon` generator | unchanged | No — deferred (DRAFT-2) |
| Environment variables | `HORIZON_URL`, `HORIZON_API_KEY` | unchanged | No — deferred (DRAFT-3) |
| Pingora module | `apps/synapse-pingora/src/horizon/*` | unchanged | No — deferred |
| Pingora config filenames | `config.horizon*.yaml` | unchanged | No — deferred |
| Historical ADRs (0001, 0002), archived/completed backlog | product name as recorded at time of writing | unchanged | No — historical accuracy preserved |

## Consequences

### Acceptable inconsistency (during the deferral window)

After m-9 ships, the repo has a deliberate contradiction that reads strangely on first encounter:

- A contributor clones the repo, cds into `apps/signal-horizon/api/`, reads the README at the top of that directory, and sees "Synapse Fleet."
- They grep the source and find `HorizonClient`, `horizonStore`, `HORIZON_URL`.
- They open `package.json` and see `"name": "@atlascrew/synapse-fleet"`.

This inconsistency is **intentional, documented, and scheduled for resolution** when the internal rename gets picked up (DRAFT-1 / DRAFT-2 / DRAFT-3). A new contributor who spots it and files "you forgot to rename X" should be pointed at this ADR and at the draft tasks. The inconsistency is not a bug; it is the load-bearing simplification that lets the public rename ship faster than the internal one.

### Customer-visible impact

- Anyone running `docker pull nickcrew/horizon:latest` or `npm install @atlascrew/horizon` in an unattended deployment script at cutover will stop receiving updates. This is the clean-cutover cost.
- Anyone reading the GitHub Pages documentation will see a product they can no longer find by the old name in the package registries.
- Mitigation is entirely in release notes + the Docker Hub / npm deprecation README updates. No code-level compat layer is cheap enough to be worth building for this, and the dual-publish alternative was rejected (see below).

### Operational

- `.github/workflows/publish-docker.yml` and `publish-npm.yml` both publish to the new targets after the cutover. No registry authentication changes are required; the Docker Hub token already has permission to push to new repos in the `nickcrew` namespace, and the npm token covers the `@atlascrew` scope.
- The old Docker Hub repo `nickcrew/horizon` and npm package `@atlascrew/horizon` are not unpublished. Unpublishing would break users who pin to specific old versions. They simply stop receiving new tags / versions.
- The cutover release tag should be a standalone release, not bundled with unrelated feature work. A bisect across the rename boundary is already going to be confusing; don't compound it with "but also we changed three features in the same release."

### Separation of concerns

- **This ADR does not decide** when the internal rename happens, only that it is separate. DRAFT-1 / DRAFT-2 / DRAFT-3 are ready-to-schedule tasks; whoever picks them up gets to make the scheduling call.
- **This ADR does not decide** pingora module or config filename renaming. That was already out of scope for Phase 3 as originally planned and stays out here.
- **This ADR does not apply** to other sub-products (Apparatus, Crucible, command-plane) that are also slated for "Synapse {name}" consolidation per the brand-consolidation plan. Each gets its own phasing decision when its time comes.

## Rejected alternatives

- **Dual-publish for a deprecation window** — publish `@atlascrew/horizon` and `@atlascrew/synapse-fleet` to the same version stream for N releases, same for Docker. Rejected because the old package's README on npm/Docker Hub can only carry a deprecation notice *after* we intentionally break its update stream, and dual-publishing delays that signal. Clean cutover pushes the rename harder and is easier to communicate in a release note than "we published the same thing under two names for six months."
- **Big-bang rename of repo + packages + symbols + env vars in one PR** — rejected for the reasons in Context. Merge-conflict amplitude with every in-flight feature branch, bisect hazard, and a single reviewer would need to hold all of it in their head. The small-PR discipline protects reviewer quality.
- **Rename the pingora `horizon/` module as part of this phase** — rejected because the abstraction ("the far side of the tunnel") is brand-agnostic, and renaming it to `fleet/` prematurely welds it to a specific product name. A later Pingora refactor (separate ADR) can consider whether the right name is `hub/`, `fleet/`, or stays `horizon/`.
- **Rename env vars without a compat layer** — not pursued because env vars aren't being renamed in this phase at all. Even when they do get renamed, the DRAFT-3 task specifies dual-accept with deprecation warning, not clean cutover, because unattended production deployments can't be expected to read a release note before their next restart.
- **Rewrite historical ADRs / shipped commit messages / archived backlog to use "Synapse Fleet"** — rejected because rewriting history makes the historical record lie. ADR-0001 was written when the product was called Horizon. That fact is part of how the decisions in ADR-0001 should be read. A cross-reference from a new document to ADR-0001 can disambiguate with "(formerly Signal Horizon)"; ADR-0001 itself stays the way it shipped.

## References

- Phase 3 umbrella context: memory `project_brand_consolidation.md`
- Package publishing setup: memory `project_package_publishing.md`
- Prior published-surface rebrand: commit `aaca417` (sidebar wordmark), commit `a6ed427` (admin console palette)
- Downstream tasks (active): TASK-89 (package rename), TASK-92 (docs rewrite)
- Downstream tasks (deferred, drafted): DRAFT-1 (directory rename), DRAFT-2 (code symbols), DRAFT-3 (env var dual-accept)
- Related ADRs: `apps/signal-horizon/docs/architecture/adr-0001-synapse-catalog-overlay.md`, `apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md`
