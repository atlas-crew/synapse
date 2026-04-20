# Synapse Fleet Dockerfile (formerly Signal Horizon — ADR-0003)
# Multi-stage build for the fleet intelligence platform.
# Directory path `apps/signal-horizon/` is unchanged; only the product name and
# published image (`nickcrew/synapse-fleet`) have been renamed.

# =============================================================================
# Builder Stage
# =============================================================================
FROM node:22-bookworm-slim AS builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /usr/src/app

# Copy workspace root files first for better layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml nx.json ./

# Copy the signal-horizon app (API, UI, shared, scripts, deploy examples)
COPY apps/signal-horizon/ ./apps/signal-horizon/

# The standalone UI build re-exports primitives from the shared signal-ui
# workspace package, so the Docker build context must include it.
COPY packages/signal-ui/ ./packages/signal-ui/

# Root LICENSE is needed by the release script
COPY LICENSE ./LICENSE

# Install all dependencies (dev included — needed for build tooling)
RUN pnpm install --frozen-lockfile

# Build the standalone release bundle (API + UI + pruned node_modules)
RUN pnpm signal-horizon:release

# =============================================================================
# Runtime Stage
# =============================================================================
FROM node:22-bookworm-slim

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r horizon && useradd -r -g horizon horizon

WORKDIR /app

# Copy the standalone bundle (dist, node_modules, prisma, bin, config)
COPY --from=builder /usr/src/app/apps/signal-horizon/out/signal-horizon-standalone/ ./

# Generate Prisma client for this platform
RUN npx prisma generate

# Set permissions
RUN chown -R horizon:horizon /app

# Synapse Fleet API default port
EXPOSE 3100

USER horizon

CMD ["node", "dist/index.js"]
