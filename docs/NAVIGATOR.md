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
