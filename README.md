# Atlas Crew Monorepo

Focused monorepo extracted from the legacy workspace with history preserved for the active Atlas Crew codebases:

- `apps/synapse-pingora`
- `apps/signal-horizon/api`
- `apps/signal-horizon/shared`
- `apps/signal-horizon/ui`
- `apps/synapse-client`
- `packages/synapse-api`

## Workspace

This repository uses `pnpm` for JavaScript/TypeScript projects and keeps `synapse-pingora` as a standalone Rust application inside the same monorepo.

### Install

```bash
pnpm install
```

### Common Commands

```bash
pnpm build
pnpm test
pnpm lint
pnpm type-check
pnpm signal-horizon:api
pnpm signal-horizon:ui
pnpm synapse-pingora:test
```

## Projects

- `apps/signal-horizon/api`: Fleet intelligence API and control plane backend
- `apps/signal-horizon/shared`: Shared Signal Horizon types and defaults
- `apps/signal-horizon/ui`: Signal Horizon dashboard UI
- `apps/synapse-client`: TypeScript CLI and client for Synapse APIs
- `packages/synapse-api`: Reusable TypeScript Synapse API package
- `apps/synapse-pingora`: Rust Pingora-based edge engine

## Notes

- Root workspace files were intentionally recreated in a fresh bootstrap commit after the history rewrite.
- Generated coverage artifacts and screenshot/site-scan history were removed during extraction.
