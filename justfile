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

# ─────────────────────────────────────────────────────────────────────────────
# DOCS SITE (VitePress)
# ─────────────────────────────────────────────────────────────────────────────

# Serve the documentation site locally
docs-dev:
    cd "{{root}}/site" && npm run dev

# Build the documentation site
docs-build:
    cd "{{root}}/site" && npm run build

# Preview the documentation site build
docs-preview:
    cd "{{root}}/site" && npm run preview

# Clean only JS/TS build artifacts (faster, skips Rust)
clean-ts:
    cd "{{root}}" && rm -rf node_modules/.cache
    cd "{{root}}/apps/signal-horizon/api" && rm -rf dist
    cd "{{root}}/apps/signal-horizon/ui" && rm -rf dist
    cd "{{root}}/apps/synapse-client" && rm -rf dist
    cd "{{root}}/packages/synapse-api" && rm -rf dist

# ─────────────────────────────────────────────────────────────────────────────
# BRAND INFOGRAPHICS
# ─────────────────────────────────────────────────────────────────────────────
#
# Author-once pipeline for brand/infographics. HTML files under
# brand/infographics/html/ are the source of truth. Each recipe renders to
# both PNG (screenshot, auto-trimmed to content) and PDF (single-page, via
# @page size inside the HTML).
#
# Requires: Google Chrome, ImageMagick (`magick`).

# Scaffold a new infographic HTML file from _template.html
infographic-new name title:
    #!/usr/bin/env bash
    set -euo pipefail
    src="{{root}}/brand/infographics/_template.html"
    dst="{{root}}/brand/infographics/html/{{name}}.html"
    if [[ -e "$dst" ]]; then
        echo "error: $dst already exists" >&2
        exit 1
    fi
    if [[ ! -e "$src" ]]; then
        echo "error: template missing at $src" >&2
        exit 1
    fi
    sed \
        -e "s|__TITLE__|{{title}}|g" \
        -e "s|__SUBTITLE__|One-sentence subtitle — replace me.|g" \
        -e "s|__TAGLINE__|Tagline — replace me.|g" \
        -e "s|__TAGLINE_SUB__|Supporting line — replace me.|g" \
        -e "s|__PAGE_HEIGHT__|1900|g" \
        "$src" > "$dst"
    echo "Created: brand/infographics/html/{{name}}.html"
    echo "Next: fill sections, then 'just infographic-render {{name}}'"

# Render one infographic (HTML → PNG + PDF). Name is the basename without .html.
infographic-render name:
    #!/usr/bin/env bash
    set -euo pipefail
    root_dir="{{root}}/brand/infographics"
    html="$root_dir/html/{{name}}.html"
    png="$root_dir/png/{{name}}.png"
    pdf="$root_dir/pdf/{{name}}.pdf"
    if [[ ! -e "$html" ]]; then
        echo "error: $html not found" >&2
        exit 1
    fi
    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if [[ ! -x "$CHROME" ]]; then
        echo "error: Google Chrome not found at $CHROME" >&2
        exit 1
    fi
    if ! command -v magick >/dev/null 2>&1; then
        echo "error: ImageMagick 'magick' not found on PATH" >&2
        exit 1
    fi

    # --- PNG: render at generous viewport, then trim + pad to 1200 wide ---
    "$CHROME" --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
        --virtual-time-budget=6000 --window-size=1200,2600 \
        --screenshot="$png" "file://$html" >/dev/null 2>&1
    magick "$png" \
        -bordercolor '#080e1a' -border 1x1 \
        -trim +repage -shave 1x1 \
        -background '#080e1a' -gravity north -extent 1200x+0+0 \
        "$png"
    height=$(magick identify -format '%h' "$png")
    echo "png: $png (1200x${height})"

    # --- PDF: headless --print-to-pdf honors @page rule inside the HTML ---
    "$CHROME" --headless=new --disable-gpu --no-sandbox \
        --no-pdf-header-footer --virtual-time-budget=6000 \
        --print-to-pdf="$pdf" "file://$html" >/dev/null 2>&1

    # --- Verify PDF is single page (count /Type /Page occurrences, robust
    #     vs freshly-written files that Spotlight hasn't indexed yet) ---
    pages=$(python3 -c 'import re,sys; d=open(sys.argv[1],"rb").read(); print(len(re.findall(rb"/Type\s*/Page(?!s)", d)))' "$pdf")
    if [[ "$pages" != "1" ]]; then
        echo "warn: pdf has $pages pages — increase @page height in $html" >&2
        exit 2
    fi
    echo "pdf: $pdf (1 page)"

# Re-render every infographic under brand/infographics/html/
infographic-render-all:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    failed=()
    for f in "{{root}}"/brand/infographics/html/*.html; do
        name=$(basename "$f" .html)
        # Skip partials / templates (underscore prefix)
        [[ "$name" == _* ]] && continue
        echo "→ $name"
        if ! just infographic-render "$name"; then
            failed+=("$name")
        fi
    done
    if (( ${#failed[@]} > 0 )); then
        echo "failed: ${failed[*]}" >&2
        exit 1
    fi
    echo "all infographics rendered"
