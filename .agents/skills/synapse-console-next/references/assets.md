# Console-Next Asset Contract

## Serving Path

The Axum admin server exposes console-next under `/console-next/` (path subject to change — verify in `admin_server.rs`):

- `GET /console-next/` → `admin_console_next_handler` returns the HTML shell.
- `GET /console-next/:path` → `admin_console_next_asset_handler` returns the matching asset from the embedded directory.

## Embedded Asset Layout

Built assets live in `apps/synapse-pingora/assets/console-next/`. The Axum handler reads from that directory at compile time (or serves from a constant map).

Expected files:

- `index.html` — shell document.
- `assets/*.js`, `assets/*.css` — hashed bundles emitted by Vite.
- `assets/*.{png,svg,woff2,...}` — static media.

## Hash/Path Rules

- **Relative URLs only.** `index.html` must reference assets as `./assets/...` or `assets/...`, never `/assets/...`. The admin server may be mounted at a non-root path.
- **Hashed filenames.** Vite produces `<name>.<hash>.js`. Do not strip hashes. The handler serves by exact filename match.
- **No CDN references.** All assets must be local so the embedded console works in air-gapped deployments.

## Vite Config Contract

- `base: './'` — critical for relative asset paths.
- `build.outDir`: points at `apps/synapse-pingora/assets/console-next/` (or is synced there post-build).
- `build.assetsInlineLimit`: keep low so small assets stay as files (easier to debug embedded serving).

## Sync Validation

`scripts/check_console_sync.cjs` compares:

1. File list in `apps/synapse-console-ui/dist/` vs `apps/synapse-pingora/assets/console-next/`.
2. Content hashes for each matching file.

Any mismatch means the compiled bundle in the Rust tree is stale — rebuild and re-sync.
