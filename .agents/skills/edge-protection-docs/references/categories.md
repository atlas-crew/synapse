# Documentation Categories

Detailed map of where different document types live in the Edge Protection ecosystem.

## User-facing (VitePress site under `site/`)

Public documentation that is published to GitHub Pages on merge.

| Category | Path | Description |
|----------|------|-------------|
| **Getting Started** | `site/getting-started/` | Quickstart, installation, and demo mode. |
| **Deployment** | `site/deployment/` | Production checklists, Docker, and K8s. |
| **Architecture**| `site/architecture/` | High-level system-level maps and flow diagrams. |
| **Configuration**| `site/configuration/` | Config references and feature toggles. |
| **Reference** | `site/reference/` | API references, feature inventories, and CLI guides. |
| **Developer** | `site/development/` | Public-facing developer overview. |

## Developer-only (Internal notes under `docs/`)

Engineering-only content that stays out of the public docs site.

| Category | Path | Description |
|----------|------|-------------|
| **Core Architecture** | `docs/architecture/` | Implementation-level diagrams and service maps. |
| **Troubleshooting** | `docs/development/` | Known issues, recovery recipes, and demo help. |
| **Implementation Plans** | `docs/development/plans/` | ADRs, design memos, and phased roadmap plans. |
| **Analysis Reports** | `docs/development/reports/` | Audits, benchmark reports, and gap analyses. |
| **Reference Data** | `docs/reference/` | Parity maps, internal registries, and audit logs. |

## Documentation Navigator
Always consult [docs/NAVIGATOR.md](../../../docs/NAVIGATOR.md) before creating a developer doc to find existing related content and ensure the INTERNAL map is up to date.
