# Atlas Crew Monorepo

Edge protection and fleet intelligence platform. A polyglot monorepo containing a Rust-based WAF/edge engine, a Node.js fleet intelligence API, a React dashboard, and supporting TypeScript libraries.

## Architecture

```
apps/
  signal-horizon/
    api/        → Fleet intelligence API (Node.js, Express, Prisma)
    ui/         → Dashboard (React 19, Vite, Tailwind)
    shared/     → Shared types and defaults
  synapse-pingora/  → Edge WAF engine (Rust, Cloudflare Pingora)
  synapse-client/   → CLI and client for Synapse APIs (TypeScript)

packages/
  synapse-api/  → Reusable Synapse API client library (TypeScript)
```

**Signal Horizon** is the fleet intelligence control plane — it aggregates telemetry from edge sensors, correlates attack campaigns, and drives collective defense decisions across a fleet of Synapse nodes.

**Synapse Pingora** is a high-performance WAF and edge proxy built on Cloudflare's Pingora framework. It handles request inspection, entity tracking, risk scoring, DLP scanning, behavioral blocking, and campaign correlation at the edge.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Node.js](https://nodejs.org) | >= 20 | TypeScript projects |
| [pnpm](https://pnpm.io) | >= 10 | Package management |
| [Rust](https://rustup.rs) | stable | Synapse Pingora |
| [just](https://github.com/casey/just) | >= 1.0 | Task runner |

## Getting Started

```bash
# Install JS/TS dependencies
just install

# Start everything in parallel (API :3100, UI :5180, Synapse :6190/:6191)
just dev
```

## Development

All common tasks are available through the root `justfile`. Run `just` to see the full list.

### Dev Servers

```bash
just dev            # All services in parallel
just dev-horizon    # Signal Horizon API + UI only
just dev-synapse    # Synapse Pingora only
```

### Build

```bash
just build                # All projects (Nx dependency graph)
just build-horizon        # Signal Horizon API + UI
just build-synapse        # Synapse Pingora (release)
just build-synapse-dev    # Synapse Pingora (debug, faster compile)
just build-synapse-api    # synapse-api library
just build-synapse-client # synapse-client CLI
```

### Test

```bash
just test               # Everything
just test-horizon       # Signal Horizon API + UI
just test-synapse       # Synapse Pingora (cargo test)
just test-synapse-heavy # Synapse Pingora integration tests
just test-synapse-api   # synapse-api library
just test-synapse-client # synapse-client CLI
```

### Lint & Type-Check

```bash
just lint           # ESLint + Clippy across all projects
just type-check     # TypeScript type-checking
just check-synapse  # Clippy + rustfmt check
just fmt-synapse    # Auto-format Rust code
```

### CI

```bash
just ci       # Full pipeline: lint → type-check → build → test
just ci-ts    # TypeScript projects only
just ci-rust  # Rust only (clippy, build, test)
```

### Database (Signal Horizon)

```bash
just db-migrate   # Run Prisma migrations (dev)
just db-seed      # Seed the database
just db-reseed    # Reset + reseed
just db-studio    # Open Prisma Studio
```

## Releasable Artifacts

| Artifact | Path | Type |
|----------|------|------|
| Signal Horizon | `apps/signal-horizon/` | API + UI (container) |
| Synapse Pingora | `apps/synapse-pingora/` | Rust binary |
| synapse-api | `packages/synapse-api/` | npm package |
| synapse-client | `apps/synapse-client/` | npm package / CLI |

## Workspace Tooling

- **[pnpm](https://pnpm.io)** — package management with workspaces
- **[Nx](https://nx.dev)** — build orchestration and dependency graph (`just graph` to visualize)
- **[just](https://github.com/casey/just)** — task runner (root `justfile`)
- **[Cargo](https://doc.rust-lang.org/cargo/)** — Rust build system (self-contained within `synapse-pingora`)

Synapse Pingora also has its own `justfile` at `apps/synapse-pingora/justfile` with demo and service management recipes.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

Synapse Pingora is licensed under Apache-2.0.
