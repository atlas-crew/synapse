---
title: Building
---

# Building from Source

::: info For contributors
Pre-built packages are available via [Docker and npm](../getting-started/installation). Building from source is only needed if you're modifying the platform.
:::

## All Projects

```sh
just build
```

This uses Nx to resolve the dependency graph and build in the correct order.

## Horizon (TypeScript)

```sh
# API + UI
just build-horizon

# Individual projects
pnpm exec nx run signal-horizon-api:build
pnpm exec nx run signal-horizon-ui:build
```

## Synapse (Rust)

```sh
# Release build (optimized, slower compile)
just build-synapse

# Debug build (faster compile, no optimizations)
just build-synapse-dev
```

For maximum performance with native CPU instructions:

```sh
cd apps/synapse-pingora
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

::: info LTO and codegen units
The release profile uses fat LTO with a single codegen unit for maximum optimization. This makes compilation slower but produces a faster binary.
:::

## Synapse Docker Image

```sh
cd apps/synapse-pingora
docker build -t synapse-waf:latest .
```

The multi-stage Dockerfile:

1. **Builder** — `rust:1.77-bookworm` with cmake, openssl, clang
2. **Runtime** — `debian:bookworm-slim`, non-root user, ~50 MB

## Client Libraries

```sh
# synapse-api package
just build-synapse-api

# synapse-client CLI
just build-synapse-client
```

## Nx Dependency Graph

Visualize the build graph:

```sh
pnpm exec nx graph
```

This opens a browser with an interactive visualization of project dependencies and build order.
