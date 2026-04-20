---
name: edge-protection-release
description: Cut and publish releases for Synapse Fleet (npm + Docker) and Synapse WAF (Docker). Use when bumping versions, tagging releases, or diagnosing CI publish workflows under .github/workflows/publish-*.yml.
---

# Edge Protection Release & Publishing

Publishing spans two products and three targets:

| Product        | npm                          | Docker Hub                   | Workflow                        |
|----------------|------------------------------|------------------------------|---------------------------------|
| Synapse Fleet  | `@atlascrew/synapse-fleet`   | `nickcrew/synapse-fleet`     | `publish-npm.yml`, `publish-docker.yml` |
| Synapse WAF    | —                            | `nickcrew/synapse-waf`       | `publish-synapse.yml`           |

Legacy names (`@atlascrew/horizon`, `nickcrew/horizon`) are deprecated. Do not cut new tags with legacy names.

## Tag Conventions

- **Synapse WAF**: `synapse-waf-v<semver>` → triggers `publish-synapse.yml`.
- **Synapse Fleet (Docker)**: release branch `release/synapse-fleet-publish-YYYYMMDD` → `publish-docker.yml`.
- **Synapse Fleet (npm)**: tag or release dispatch → `publish-npm.yml`.

Every `publish-*.yml` supports `workflow_dispatch` with a `dry_run` input for validation.

## Common Pitfalls (from recent commit history)

- **Docker tag drift**: `publish-docker.yml` historically pushed `:latest` without explicit semver tags. Always verify the version tag is emitted alongside `latest` — see fix in commit `b859dba`.
- **Missing signal-ui in build**: The Fleet Docker image must include `packages/signal-ui` in its build context — see `1764d58`.
- **Stale Docker tags**: Use the dedicated deletion workflow (`d6d991c` introduced it, `a0e8017` folded it into publish). Don't delete tags manually via the web UI.

## Bundled Utilities

- **`scripts/check_publish_tags.cjs`**: Compares the version in `apps/signal-horizon/api/package.json`, `ui/package.json`, `packages/synapse-api/package.json` and flags mismatches before cutting a release.
  - Usage: `node scripts/check_publish_tags.cjs`

## Workflow

1. **Pre-flight**: Run `just ci` end-to-end. Never cut a release with a failing CI.
2. **Version sync**: Bump versions in all relevant `package.json` files (use the bundled check script).
3. **Tag**: Follow tag convention above. Push tag, then watch the workflow.
4. **Dry-run first**: For WAF or first-time releases, dispatch with `dry_run: true`.
5. **Post-publish**: Verify on Docker Hub (`nickcrew/*`) and npm (`@atlascrew/*`) that tags appeared.

## Resources

- [Workflow Map](references/workflows.md): Input/output of each `publish-*.yml` file.
- [Versioning Rules](references/versioning.md): Semver policy, pre-release handling, release-branch naming.
