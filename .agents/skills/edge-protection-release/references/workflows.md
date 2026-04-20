# Publish Workflows

All publish workflows live under `.github/workflows/`.

## `publish-synapse.yml` — Synapse WAF Docker

- **Trigger**: `push` tag matching `synapse-waf-v*`, or `workflow_dispatch` with `dry_run`.
- **Working directory**: `apps/synapse-pingora`.
- **Toolchain**: `dtolnay/rust-toolchain@nightly` with rustfmt + clippy.
- **Cache**: `Swatinem/rust-cache@v2` scoped to the crate.
- **System deps**: cmake, libssl-dev, libclang-dev, pkg-config.
- **Output**: `nickcrew/synapse-waf:<version>` + `:latest`.

## `publish-docker.yml` — Synapse Fleet Docker

- **Trigger**: release branch push (`release/synapse-fleet-publish-*`), workflow_dispatch.
- **Build context**: must include `packages/signal-ui/` (fixed in `1764d58`).
- **Tags emitted**: explicit semver + `:latest` (fixed in `b859dba` — don't regress).
- **Output**: `nickcrew/synapse-fleet:<version>` + `:latest`.
- **Cleanup**: Old tags deleted via the folded-in cleanup step (`a0e8017`).

## `publish-npm.yml` — Synapse Fleet npm

- **Trigger**: tag / workflow_dispatch.
- **Published packages**: `@atlascrew/synapse-fleet`, plus any `packages/*` that have a `publishConfig`.
- **Provenance**: uses GitHub OIDC for npm provenance — do not disable.

## `signal-horizon-preflight.yml` / `signal-horizon-quality.yml`

- **Preflight**: fast checks on PR (lint + type-check).
- **Quality**: deeper checks (tests, coverage, bundle size) on merge to `main`.

## Dispatch Cheat-Sheet

```bash
# Dry-run a WAF release
gh workflow run publish-synapse.yml -f dry_run=true

# Publish Fleet Docker from a release branch
git checkout -b release/synapse-fleet-publish-$(date +%Y%m%d)
git push -u origin HEAD
# workflow fires on push

# Publish Fleet npm
git tag @atlascrew/synapse-fleet@<version> && git push --tags
```
