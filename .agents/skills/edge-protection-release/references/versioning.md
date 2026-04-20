# Versioning Rules

## Semver Policy

- **MAJOR**: Breaking changes to the sensor protocol, admin API, or Fleet → Sensor message schema.
- **MINOR**: Additive features (new WAF rules, new admin endpoints, new UI routes).
- **PATCH**: Bug fixes, docs, internal refactors that don't change public contracts.

## Synapse Fleet vs Synapse WAF

- Versions are independent. Do not synchronize them.
- A Fleet bump does not require a WAF bump, and vice versa.
- Sensor-Fleet compatibility is declared in `apps/signal-horizon/shared/src/protocol-version.ts`. Bump there when the wire format changes.

## Pre-Releases

- Pre-release tags: `<name>@<version>-rc.<n>` or `<name>@<version>-beta.<n>`.
- Pre-releases go to Docker Hub with the same tag (not `:latest`) and to npm with the `next` dist-tag.

## Release Branch Naming

- Fleet Docker: `release/synapse-fleet-publish-YYYYMMDD`.
- WAF Docker: use a tag (`synapse-waf-v<version>`), not a branch.

## Legacy Names — Do Not Use

- `@atlascrew/horizon` (npm) — deprecated.
- `nickcrew/horizon` (Docker Hub) — deprecated.

Publishing under legacy names will confuse consumers who already migrated to `synapse-fleet`. If you see a workflow publishing under a legacy name, treat it as a bug.

## Version Sync Across Packages

Before cutting a Fleet release, these `package.json` files must agree on the version:

- `apps/signal-horizon/api/package.json`
- `apps/signal-horizon/ui/package.json`
- `apps/signal-horizon/shared/package.json`
- `packages/synapse-api/package.json`
- `packages/signal-ui/package.json`

Use the bundled `check_publish_tags.cjs` script to verify before tagging.
