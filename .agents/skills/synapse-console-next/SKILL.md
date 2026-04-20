---
name: synapse-console-next
description: Develop the embedded Synapse WAF admin console SPA (apps/synapse-console-ui) and manage its compiled assets shipped inside the Rust binary. Use when modifying the per-sensor admin UI, its bundled output, or the Axum asset handlers that serve it.
---

# Synapse Console-Next Strategy

The Synapse WAF ships with an embedded React SPA — the "console-next" — which is served directly by the Rust binary over the admin port. Unlike the Synapse Fleet dashboard (which is a separate deployable), console-next lives inside the WAF process.

## Surface Map

- **Source**: `apps/synapse-console-ui/` — Vite + React SPA. Entry: `src/App.tsx`, `src/main.tsx`.
- **Compiled assets**: `apps/synapse-pingora/assets/console-next/` — the built JS/CSS bundle committed to the repo. Shipped inside the binary via `include_bytes!` or asset routes.
- **Axum handlers**: In `admin_server.rs`:
  - `admin_console_next_handler` — serves the HTML shell.
  - `admin_console_next_asset_handler` — serves hashed JS/CSS under a path prefix.

## Build → Ship Pipeline

1. Edit source under `apps/synapse-console-ui/src/`.
2. Build: `pnpm --filter synapse-console-ui build`.
3. Sync the output into `apps/synapse-pingora/assets/console-next/`.
4. Rebuild the WAF binary so the new assets are embedded.
5. Commit source + compiled assets together — drift between the two breaks the embedded console.

## Rules (different from Synapse Fleet UI)

- **No `@/ui` import**: This SPA does NOT consume the Apparatus design system. It is deliberately minimal — Tailwind + native elements only.
- **No BullMQ / Prisma / React Query**: This is a standalone admin panel. It talks to the local admin API over fetch, nothing else.
- **Bundle size matters**: Assets are embedded in the Rust binary. Keep the bundle lean. Avoid heavy chart libs.
- **Path-prefix safety**: All asset URLs must be relative (no leading `/`) so the console works regardless of where the admin server is mounted.

## Bundled Utilities

- **`scripts/check_console_sync.cjs`**: Verifies that `apps/synapse-pingora/assets/console-next/` is in sync with the last build output by comparing file lists and content hashes.
  - Usage: `node scripts/check_console_sync.cjs`

## Workflow

1. **Source edit**: Work under `apps/synapse-console-ui/src/`.
2. **Type & test**: `pnpm --filter synapse-console-ui test` and `type-check`.
3. **Build**: `pnpm --filter synapse-console-ui build`.
4. **Sync**: Copy output to `apps/synapse-pingora/assets/console-next/`. Run the sync-check script.
5. **Rebuild WAF**: `just build-synapse` so the new bundle ships.
6. **Commit together**: Source + compiled assets in one atomic commit.

## Resources

- [Asset Contract](references/assets.md): How the Axum handlers serve the SPA; hash/path rules.
- [Minimalism Policy](references/minimalism.md): Why this SPA stays dependency-light.
