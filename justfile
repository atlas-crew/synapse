# Atlas Crew Monorepo — Development Justfile
# Usage: just <recipe>   |   just --list

set dotenv-load := false
set positional-arguments := true

# Root directory of the monorepo
root := justfile_directory()

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT
# ─────────────────────────────────────────────────────────────────────────────

# Show available recipes
default:
    @just --list --unsorted

# ─────────────────────────────────────────────────────────────────────────────
# DEV SERVERS
# ─────────────────────────────────────────────────────────────────────────────

# Start Signal Horizon API + UI in parallel
dev-horizon:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting Signal Horizon API (port 3100) + UI (port 5180)..."
    trap 'kill 0' EXIT
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:dev &
    cd "{{root}}" && pnpm exec nx run signal-horizon-ui:dev &
    wait

# Start Synapse Pingora in dev mode
dev-synapse:
    cd "{{root}}" && pnpm exec nx run synapse-pingora:dev

# Start everything: Signal Horizon + Synapse Pingora in parallel
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting all services..."
    echo "  Signal Horizon API → :3100"
    echo "  Signal Horizon UI  → :5180"
    echo "  Synapse Pingora    → :6190 (proxy) / :6191 (admin)"
    trap 'kill 0' EXIT
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:dev &
    cd "{{root}}" && pnpm exec nx run signal-horizon-ui:dev &
    cd "{{root}}" && pnpm exec nx run synapse-pingora:dev &
    wait

# ─────────────────────────────────────────────────────────────────────────────
# BUILD
# ─────────────────────────────────────────────────────────────────────────────

# Build all projects (respects Nx dependency graph)
build:
    cd "{{root}}" && pnpm exec nx run-many --target=build --all

# Build only Signal Horizon (API + UI + shared)
build-horizon:
    cd "{{root}}" && pnpm exec nx run-many --target=build --projects=signal-horizon-api,signal-horizon-ui

# Build Synapse Pingora (release)
build-synapse:
    cd "{{root}}/apps/synapse-pingora" && cargo build --release

# Build Synapse Pingora (debug, faster compile)
build-synapse-dev:
    cd "{{root}}/apps/synapse-pingora" && cargo build

# Build synapse-api package
build-synapse-api:
    cd "{{root}}" && pnpm exec nx run synapse-api:build

# Build synapse-client
build-synapse-client:
    cd "{{root}}" && pnpm exec nx run synapse-client:build

# ─────────────────────────────────────────────────────────────────────────────
# TEST
# ─────────────────────────────────────────────────────────────────────────────

# Run all tests across the monorepo
test:
    cd "{{root}}" && pnpm exec nx run-many --target=test --all

# Test Signal Horizon (API + UI)
test-horizon:
    cd "{{root}}" && pnpm exec nx run-many --target=test --projects=signal-horizon-api,signal-horizon-ui

# Test Signal Horizon API only
test-horizon-api:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:test

# Test Signal Horizon UI only
test-horizon-ui:
    cd "{{root}}" && pnpm exec nx run signal-horizon-ui:test

# Test Synapse Pingora
test-synapse:
    cd "{{root}}/apps/synapse-pingora" && cargo test

# Test Synapse Pingora (heavy / integration tests)
test-synapse-heavy:
    cd "{{root}}/apps/synapse-pingora" && cargo test --features heavy-tests

# Test synapse-api package
test-synapse-api:
    cd "{{root}}" && pnpm exec nx run synapse-api:test

# Test synapse-client
test-synapse-client:
    cd "{{root}}" && pnpm exec nx run synapse-client:test

# ─────────────────────────────────────────────────────────────────────────────
# LINT & TYPE-CHECK
# ─────────────────────────────────────────────────────────────────────────────

# Lint everything
lint:
    cd "{{root}}" && pnpm exec nx run-many --target=lint --all

# Type-check all TypeScript projects
type-check:
    cd "{{root}}" && pnpm exec nx run-many --target=type-check --all

# Lint + type-check Synapse Pingora (clippy + fmt check)
check-synapse:
    cd "{{root}}/apps/synapse-pingora" && cargo clippy && cargo fmt -- --check

# Format Synapse Pingora Rust code
fmt-synapse:
    cd "{{root}}/apps/synapse-pingora" && cargo fmt

# ─────────────────────────────────────────────────────────────────────────────
# CI — full validation pipeline
# ─────────────────────────────────────────────────────────────────────────────

# Run the full CI pipeline: lint, type-check, build, test
ci: lint type-check build test

# CI for TypeScript projects only
ci-ts: lint type-check
    cd "{{root}}" && pnpm exec nx run-many --target=build --all --exclude=synapse-pingora
    cd "{{root}}" && pnpm exec nx run-many --target=test --all --exclude=synapse-pingora

# CI for Synapse Pingora (Rust) only
ci-rust: check-synapse build-synapse test-synapse

# ─────────────────────────────────────────────────────────────────────────────
# SERVICES (local infrastructure)
# ─────────────────────────────────────────────────────────────────────────────

# Check status of all local services
services:
    #!/usr/bin/env bash
    check() {
        local name="$1" port="$2"
        if lsof -i :"$port" -P 2>/dev/null | grep -q LISTEN; then
            echo "  $name (:$port): UP"
        else
            echo "  $name (:$port): DOWN"
        fi
    }
    echo "Local services:"
    check "Redis"      6379
    check "PostgreSQL"  5432
    check "ClickHouse" 8123

# Start ClickHouse server via launchd
ch-start:
    launchctl load ~/Library/LaunchAgents/local.clickhouse-server.plist 2>/dev/null || true
    @sleep 2
    @curl -sf http://localhost:8123/ping > /dev/null && echo "ClickHouse running on :8123" || echo "ClickHouse failed to start — check /opt/homebrew/var/log/clickhouse/stderr.log"

# Stop ClickHouse server
ch-stop:
    launchctl unload ~/Library/LaunchAgents/local.clickhouse-server.plist 2>/dev/null || true
    @echo "ClickHouse stopped"

# Initialize the Signal Horizon ClickHouse schema
ch-init:
    clickhouse client --query "CREATE DATABASE IF NOT EXISTS signal_horizon"
    cd "{{root}}" && clickhouse client --database signal_horizon --multiquery --queries-file apps/signal-horizon/clickhouse/schema.sql
    @echo "ClickHouse signal_horizon schema initialized"

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE (Signal Horizon — PostgreSQL)
# ─────────────────────────────────────────────────────────────────────────────

# Generate Prisma client
db-generate:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:generate

# Run database migrations (dev)
db-migrate:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:migrate

# Deploy database migrations (production)
db-migrate-prod:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:migrate:prod

# Open Prisma Studio
db-studio:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:studio

# Seed the database
db-seed:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:seed

# Reset and reseed the database (default profile)
db-reseed:
    cd "{{root}}" && pnpm exec nx run signal-horizon-api:db:reseed

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARKS (Synapse Pingora)
# ─────────────────────────────────────────────────────────────────────────────

# Run Synapse Pingora benchmarks
bench-synapse:
    cd "{{root}}/apps/synapse-pingora" && cargo bench

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

# Install dependencies
install:
    cd "{{root}}" && pnpm install

# Visualize the Nx project dependency graph
graph:
    cd "{{root}}" && pnpm exec nx graph

# Clean all build artifacts
clean:
    cd "{{root}}" && rm -rf node_modules/.cache
    cd "{{root}}/apps/signal-horizon/api" && rm -rf dist
    cd "{{root}}/apps/signal-horizon/ui" && rm -rf dist
    cd "{{root}}/apps/synapse-client" && rm -rf dist
    cd "{{root}}/packages/synapse-api" && rm -rf dist
    cd "{{root}}/apps/synapse-pingora" && cargo clean

# Clean only JS/TS build artifacts (faster, skips Rust)
clean-ts:
    cd "{{root}}" && rm -rf node_modules/.cache
    cd "{{root}}/apps/signal-horizon/api" && rm -rf dist
    cd "{{root}}/apps/signal-horizon/ui" && rm -rf dist
    cd "{{root}}/apps/synapse-client" && rm -rf dist
    cd "{{root}}/packages/synapse-api" && rm -rf dist
