# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository shape

Polyglot Nx + pnpm monorepo. Three toolchains:

- **Rust (nightly + Cargo)** — `apps/synapse-pingora/` is the Synapse WAF, a Pingora-based reverse proxy + WAF. Self-contained Cargo crate (`synapse-waf` bin, `synapse_pingora` lib) with its own `justfile` for demo/service recipes.
- **Node.js 20+ / TypeScript** — `apps/signal-horizon/{api,ui,shared}` is the fleet intelligence control plane (Express + Prisma + Vite/React 19). Other TS projects: `apps/synapse-client` (CLI), `apps/synapse-console-ui` (embedded admin console SPA), `packages/synapse-api` (client library), `packages/signal-ui`.
- **pnpm workspace** — `pnpm-workspace.yaml` globs `apps/*`, `apps/signal-horizon/*`, and `packages/*`. `@atlascrew/apparatus-lib` is pnpm-linked to `../Apparatus/libs/client` (sibling checkout).

Nx orchestrates TS builds (`targetDefaults.build.dependsOn = ["^build"]`) so `@signal-horizon/shared` compiles before the API/UI consume it. The Rust crate is outside the Nx graph for build purposes but is wired into Nx targets (`nx run synapse-waf:dev|test`).

## Canonical commands (root `justfile`)

Use `just <recipe>` — these wrap pnpm/Nx/Cargo so you don't have to remember the incantation. `just --list` shows everything.

### Dev servers (tmux-backed)

```bash
just dev              # All services in a shared tmux session `edge-protection`
just dev-horizon      # Horizon API + UI only
just dev-synapse      # Synapse WAF only
just dev-status       # Per-window running/idle/not-running
just dev-tail <name>  # Tail last N lines from a window
just dev-stop         # Stop all windows
just demo             # Horizon + release-build synapse-waf --demo + Apparatus + Chimera
just demo-fleet       # Same as demo but with 3 synapse-waf sensors (ports 6190/6290/6390)
```

Dev servers run in tmux windows (not foreground). The session survives terminal exits. Attach with `just dev-shell`.

### Build / test / lint (all paths route through `just`)

```bash
just build            # All via Nx
just build-synapse    # cargo build --release (crate is outside Nx build target)
just test             # All via Nx
just test-synapse     # cargo test
just test-synapse-heavy        # cargo test --features heavy-tests
just lint             # Nx lint (ESLint) — does NOT include clippy
just check-synapse    # clippy + rustfmt --check
just type-check       # tsc --noEmit across TS projects
just ci               # lint → type-check → build → test
just ci-ts / just ci-rust      # Per-stack CI
```

### Running a single test

- Vitest (any TS project): `pnpm --filter <pkg> test -- <pattern>` or from the project dir `pnpm exec vitest run <file>`.
- Nx-scoped single test: `pnpm exec nx run signal-horizon-api:test -- <pattern>`.
- Cargo: `cd apps/synapse-pingora && cargo test <test_name>` (append `-- --nocapture` for println output).

### Database (Signal Horizon)

```bash
just db-generate              # Prisma generate
just db-migrate               # Prisma migrate dev
just db-migrate-status        # Drift check (read-only)
just db-seed / db-reseed      # Seed / reset+seed
just db-reseed-medium|large   # Seed with larger volume profiles
just db-reset                 # DESTRUCTIVE: drops all data, runs migrations, no seed
just ch-start / ch-stop       # ClickHouse launchd control
just ch-init                  # Apply signal_horizon schema to ClickHouse
just services                 # Port-check Redis 6379 / Postgres 5432 / ClickHouse 8123
```

PostgreSQL holds configuration + relational data. ClickHouse holds time-series telemetry. Redis handles session state and BullMQ queues.

## Architecture overview

### Synapse WAF (`apps/synapse-pingora/`)

Single Rust binary that inspects every request in-process (no serialization boundaries). Pipeline: ACL → rate limit → tarpit → WAF rules → DLP → entity tracking → proxy. Major subsystems as top-level `src/` modules: `waf/`, `dlp/`, `detection/`, `entity/`, `actor/`, `session/`, `correlation/`, `interrogator/`, `horizon/` (client to Signal Horizon hub), `admin_server.rs` (Axum 90+ endpoint admin API), `config_manager.rs` + `reload.rs` (hot-reload via atomic swap), `tunnel/` (encrypted hub connectivity), `simulator.rs` (procedural traffic for `--demo`).

Ports: `:6190` proxy, `:6191` admin (multiple configs under `config.*.yaml` for fleet demos — `config.horizon.yaml`, `config.horizon.2.yaml`, etc.).

### Signal Horizon (`apps/signal-horizon/`)

Fleet intelligence hub that aggregates telemetry from Synapse sensors and drives collective defense.

- **API** (`api/src/`): Express app. `index.ts` wires PrismaClient + services into gateways. WebSocket gateways under `websocket/` (`SensorGateway` ingests sensor telemetry; `DashboardGateway` fans out to UI). Service pipeline: `Aggregator → Correlator → Broadcaster`, plus `HuntService`, `APIIntelligenceService`, `FleetAggregator`, `FleetCommander`, `RuleDistributor`, `WarRoomService` + `PlaybookService`, `ImpossibleTravelService`. Background jobs in `jobs/` use BullMQ (`retention-queue`, `sigma-hunt-queue`, `blocklist-queue`). Storage split: Prisma (Postgres) for relational state + `ClickHouseService` + `ClickHouseRetryBuffer` + `FileRetryStore` for durable time-series writes with persistent retry-on-failure.
- **UI** (`ui/src/`): React 19 + Vite + Tailwind. Zustand for global state, React Query for server state. Runs on `:5180`, auto-uses dev API key `dev-dashboard-key` seeded by `db-seed`. See `apps/signal-horizon/ui/CLAUDE.md` for the mandatory component-library rules.
- **Shared** (`shared/`): types and defaults consumed via `@signal-horizon/shared` workspace import.

### Data flow

Sensors (Synapse WAF instances) push signals over WebSocket to Horizon's `SensorGateway`. The aggregator normalizes events; the correlator clusters them into campaigns; the broadcaster fans them out to dashboards and the fleet commander pushes distributed rule updates back to sensors. See `docs/architecture/platform-map.md` for the one-page operator map.

## Brand / rename state (important when touching code or docs)

"Synapse" is the unified product name consolidating "Signal Horizon" + "Synapse WAF". The rename is **phased** — do not mass-rename. Specifically:

- Directory `apps/signal-horizon/` is intentionally unchanged (see `apps/signal-horizon/docs/architecture/adr-0003-synapse-fleet-rename.md`).
- Published as `@atlascrew/synapse-fleet` (npm) and `nickcrew/synapse-fleet` (Docker Hub). Old `@atlascrew/horizon` / `nickcrew/horizon` are deprecated.
- Horizon and Synapse/Apparatus/Crucible are a **federated** aggregator + standalone products — each has its own management UI. Horizon aggregates but does not own their admin surfaces.

## Documentation layout (enforced)

See `docs/NAVIGATOR.md`. Two strict buckets:

- `site/**` — public VitePress docs that ship to GitHub Pages (`site/getting-started/`, `site/reference/`, `site/configuration/`, etc.).
- `docs/**` — developer-only notes. Sub-folders: `architecture/`, `development/` (+ `development/plans/`, `development/reports/`), `reference/`, `user-guides/`, `archive/`.

Rules: kebab-case filenames for anything under `docs/`. Do not drop new markdown in the repo root (only `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md` allowed there). Update `docs/NAVIGATOR.md` when you add a developer-facing doc.

## Git rules (from global `Cortex/rules/git-rules.md`)

- **Use `cortex git commit` / `cortex git patch` for all commits** — not `git add`. These handle staging files/hunks safely.
- Conventional commits: `<type>(scope): <summary>`. Atomic — one logical change per commit.
- No AI/Claude attribution, trailers, or co-author lines. Author must be the user's git identity.
- Never `git reset --hard` or `git checkout` to discard work without explicit permission. Resolve merge conflicts rather than nuking.
- Only commit files you modified. If a dirty file's existing changes are unrelated to yours, use `cortex git patch` to stage only your hunks; if the edits overlap, escalate instead of overwriting.

## Backlog tasks

Backlog.md is the task tracker (`backlog/` directory; `backlog/config.yml`; project `EdgeProtection`). Use the `mcp__backlog__*` MCP tools when filing deferred issues, working assigned tasks, or managing project work. Start a session by reading `backlog://workflow/overview` if backlog work is involved.

## UI agent rules

`apps/signal-horizon/ui/CLAUDE.md` is authoritative for UI work and **overrides** generic styling guidance:

- Import everything from `@/ui` (tokens, components, chart defaults). No ad-hoc styled components in page files.
- Brand constraints: Rubik font only (300 for headings, 400 for body), primary colors `colors.blue` (#0057B7) / `colors.navy` (#001E62) / `colors.magenta` (#D62598), `borderRadius: 0` everywhere, `spacing` tokens instead of raw px.
- Zustand for global state, React Query for server state, `useState` for UI-only state.

## Sibling repos (demo recipes)

`just demo` and `just demo-fleet` start sibling checkouts of `../Apparatus` (Active Defense backend) and `../Chimera` (intentionally vulnerable target). Override paths via `APPARATUS_PATH` / `CHIMERA_PATH` env vars. These are optional — `just dev` and `just dev-horizon` don't need them.

## Coding Style & Naming Conventions

TypeScript uses ESM, 2-space indentation, and `camelCase` for variables/functions with `PascalCase` for React components and types. Rust follows `rustfmt` defaults and `snake_case` for modules and functions. Keep changes scoped to the package you are editing, and favor existing names such as `synapse-*` over introducing new aliases. Run lint and type-check before handing work off.

## Testing Guidelines

Vitest is the standard test runner for the API, UI, CLI, and `packages/synapse-api`. Name tests `*.test.ts` or `*.test.tsx`; UI coverage is configured under `src/**/*.test.{ts,tsx}`. Rust tests run through Cargo, with heavier suites available through the repo recipes. Add or update tests with every behavioral change, and prefer targeted commands locally before a final `just ci`.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commits like `feat(console): ...`, `fix(synapse-waf): ...`, and `docs(horizon): ...`. Keep commits atomic and bisect-friendly. Per repo policy, commit with `cortex git commit` or `cortex git patch`, not broad staging commands. PRs should include a concise summary, linked issue or backlog task, verification commands run, and screenshots for UI changes.

#

## UI Feature Implementation

Implement UI feature using a strict test-first autonomous loop: (1) before writing any component code, author failing Vitest component tests AND a Playwright smoke test that encode the exact UI library APIs (shadcn, Radix, whatever is canonical in this repo — verify by grepping existing components first), (2) spawn a Task subagent whose only job is to make those tests pass without modifying them, (3) the subagent must run typecheck + tests after every edit and self-correct on failure, (4) only return control when typecheck is clean and all tests pass,  (5) commit with a message referencing the contract tests as the acceptance criteria. If you find yourself about to use a UI API that doesn't appear elsewhere in the repo, stop and re-verify the library choice.

## QA and Review

### Review Types

- **Outside Perspective:**  For external review by another LLM, use the `codex-code-review` or `multi-llm-consult` or `agent-loops` skill. *Reviewer: External LLM*
- **Specialist:** Reviews should be performed by specialist agents with fresh context windows. *Reviewer: Team or Sub-agent(s)*
- **Multi-perspectives:** Use the `multi-perspective-analysis` skill.  *Reviewer: Self*
- **Test:** Use the `test-review` skill to uncover gaps in behavioral testing and test quality. *Reviewer: Self*

All commits must be reviewed by specialist(s). For complex reviews, use a Team of specialist agents so that they can communicate with another and synthesize their findings. For single-concern reviews (e.g. performance, UI/UX, typescript) you can use a specialist sub-agent.

#### When to Use

- For very important work (e.g. architecture changes, large refactors) use *Outside Perspective* **AND** *Specialist*
- For medium-to-low complexity changes, you can save tokens and time with *Multi-perspective (Self Review)*
- For reviewing tests or discovering gaps in testing, use *Test*
