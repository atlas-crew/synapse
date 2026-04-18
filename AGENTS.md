# Repository Guidelines

## Project Structure & Module Organization

This repository is a pnpm/Nx monorepo for the Edge Protection platform. Main application code lives in `apps/`: `apps/signal-horizon/api` for the fleet API, `apps/signal-horizon/ui` for the React dashboard, `apps/synapse-pingora` for the Rust WAF/edge engine, and `apps/synapse-client` for the TypeScript CLI. Shared client code lives in `packages/synapse-api`. Documentation and deployment notes live in `docs/` and `site/`; brand assets live in `brand/`; backlog planning lives in `backlog/`.

## Build, Test, and Development Commands

Use the root `justfile` for day-to-day work:

- `just dev`: start the API, UI, and Synapse WAF in tmux-backed sessions.
- `just build`: build the full workspace through Nx.
- `just test`: run the main TypeScript and Rust test suites.
- `just lint`: run ESLint and Rust lint checks.
- `just type-check`: run TypeScript type-checks across the workspace.
- `just ci`: run the full local quality gate before opening a PR.

Targeted commands are preferred for faster loops, for example `just test-synapse`, `just test-horizon`, `pnpm --filter @atlascrew/signal-horizon-api test`, or `cargo test` from `apps/synapse-pingora`.

## Coding Style & Naming Conventions

TypeScript uses ESM, 2-space indentation, and `camelCase` for variables/functions with `PascalCase` for React components and types. Rust follows `rustfmt` defaults and `snake_case` for modules and functions. Keep changes scoped to the package you are editing, and favor existing names such as `synapse-*` over introducing new aliases. Run lint and type-check before handing work off.

## Testing Guidelines

Vitest is the standard test runner for the API, UI, CLI, and `packages/synapse-api`. Name tests `*.test.ts` or `*.test.tsx`; UI coverage is configured under `src/**/*.test.{ts,tsx}`. Rust tests run through Cargo, with heavier suites available through the repo recipes. Add or update tests with every behavioral change, and prefer targeted commands locally before a final `just ci`.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commits like `feat(console): ...`, `fix(synapse-waf): ...`, and `docs(horizon): ...`. Keep commits atomic and bisect-friendly. Per repo policy, commit with `cortex git commit` or `cortex git patch`, not broad staging commands. PRs should include a concise summary, linked issue or backlog task, verification commands run, and screenshots for UI changes.

## Security & Configuration Tips

PostgreSQL is required for Signal Horizon development. ClickHouse and Redis are optional for some local flows, but document when your change depends on them. Keep secrets in local `.env` files under app directories and never commit credentials, generated env files, or production tokens.
