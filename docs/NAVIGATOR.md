# Documentation Navigator

Map of where things live in this repo. User-facing content that ends up
on the GitHub Pages site lives under `site/`; developer-only content
that stays out of the public docs lives under `docs/`.

## User-facing (VitePress site → GitHub Pages)

All markdown under `site/` is built by VitePress (`site/.vitepress/config.mts`)
and published to GitHub Pages on merge. Edit these when you want the
change to be visible to end users.

- `site/getting-started/` — installation, requirements, quickstart, and
  the demo-mode walkthrough (`demo-mode.md`).
- `site/architecture/` — system-level architecture diagrams and the
  data flow between Horizon and Synapse.
- `site/deployment/` — Horizon deployment, Synapse standalone, Docker,
  Kubernetes, and the production checklist.
- `site/configuration/` — configuration references for Horizon,
  Synapse, and feature toggles.
- `site/reference/` — API references (Horizon API, Synapse API, Synapse
  CLI) and feature inventories.
- `site/development/` — public-facing developer overview (the private
  implementation notes live under `docs/development/`).

## Developer-only (stays out of the published site)

Markdown under `docs/` is for engineers working on this codebase. It
covers implementation details, troubleshooting recipes, and design
notes that are not part of the product documentation.

- [docs/architecture/platform-map.md](./architecture/platform-map.md) —
  One-page operator reference listing every service, data seam, port,
  maturity state (production / dormant-but-wired / placeholder /
  in-flight), and `just` launcher across the Edge Protection platform
  plus its `../Apparatus` and `../Chimera` siblings. Read this first
  when joining services or picking the demo back up.
- [docs/development/demo-simulator.md](./development/demo-simulator.md) —
  Architecture of the procedural traffic simulator that drives demo
  mode (archetypes, tick model, state mirrors, HorizonManager wiring).
- [docs/development/demo-troubleshooting.md](./development/demo-troubleshooting.md) —
  Known issues and recovery recipes for the demo pipeline (Prisma
  client regeneration, luma.gl dedup, sensor auth flows, RPS saturation,
  the ID-namespace schism between seed and live data).
- [docs/development/design-system-panel.md](./development/design-system-panel.md) —
  `<Panel>` component reference: semantic tones, padding/spacing tokens,
  migration guide, and the deferred work needed for full card-convention
  cleanup (slotted headers, tactical variant, `.card` CSS deprecation).
- [docs/development/plans/ui-brand-backlog.md](./development/plans/ui-brand-backlog.md) —
  Prioritised backlog of UI/brand work: Synapse admin console overhaul,
  Horizon typography harmonisation, form control audit, visual regression
  tests, bundle splitting, and other open threads from the design system
  overhaul.
- [docs/development/plans/synapse-admin-console-audit.md](./development/plans/synapse-admin-console-audit.md) —
  Gap analysis of the Synapse sensor admin console vs. its admin API.
  Inventories observability endpoints, per-site CRUD, global server
  settings, module configs, and runtime ops. Proposes a reorganised
  IA and prioritised implementation order. Read this before expanding
  the admin console.
- [docs/development/plans/commercial-viability-and-pricing.md](./development/plans/commercial-viability-and-pricing.md) —
  Strategy memo (2026-04-20) on OSS commercialisation direction:
  technical-maturity scorecard, enterprise procurement gaps, community
  governance gaps, managed-vs-open-core decision (recommendation: hybrid
  with managed hub + self-host enterprise), published pricing tiers with
  specific numbers, 3-year revenue trajectory, and phased roadmap.
  Read before shaping pricing pages, commercial licence terms, or
  go-to-market priorities.
- [docs/reference/synapse-infographic-coverage.md](./reference/synapse-infographic-coverage.md) —
  Parity map between the Synapse Technical Reference PDF (25 sections)
  and the one-page infographics in `brand/infographics/`. Marks each
  PDF section as Full / Partial / None and ranks the gaps as a
  prioritised backlog of proposed new infographics. Read this before
  commissioning new brand visuals or auditing doc/asset parity.
- [docs/reference/synapse-site-coverage.md](./reference/synapse-site-coverage.md) —
  Parity map between the Synapse Technical Reference PDF (25 sections)
  and the VitePress site under `site/`. 19 full / 6 partial / 0 none.
  All gaps are "deepen in place" — no topic is absent. Ranks the six
  partials as a prioritised deepening backlog.
- [docs/reference/horizon-site-coverage.md](./reference/horizon-site-coverage.md) —
  Parity map between the Signal Horizon Technical Reference PDF
  (8 sections + 2 appendices) and the site. 9 full / 1 partial. Notes
  the in-flight Horizon → Synapse Fleet rename: authoritative content
  now lives under `synapse-fleet*.md`; `horizon-*.md` are redirect stubs
  pending removal. Includes a rename-cleanup checklist tied to
  milestone m-9.
- `docs/dockerhub-horizon.md`, `docs/dockerhub-synapse-waf.md` — Docker
  Hub registry publishing notes.

## When to add a new document

- **User-facing**: place under `site/` in the matching section and add
  it to the sidebar in `site/.vitepress/config.mts`.
- **Developer-facing**: place under `docs/development/` (or a new
  subdirectory for another category) and add a line to this navigator.
- Use kebab-case filenames. Do not create markdown in the repo root
  without asking — exceptions are `README.md`, `CONTRIBUTING.md`, and
  `CHANGELOG.md`.
