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
# DEV SERVERS (tmux-backed)
# ─────────────────────────────────────────────────────────────────────────────
#
# Each long-running dev server runs in its own tmux window inside a shared
# session. Replaces the old `trap 'kill 0' EXIT` foreground pattern:
#   - services survive terminal exits
#   - logs don't interleave
#   - each window can be started, stopped, tailed, or restarted independently
#
# Session name: $TMUX_SESSION or `edge-protection` (default).
# Attach:       `just dev-shell`
# Status:       `just dev-status`
# Stop all:     `just dev-stop`

_dev_session := env_var_or_default("TMUX_SESSION", "edge-protection")

# Ensure the tmux session exists (idempotent, detached)
_dev-init:
    @tmux has-session -t "{{_dev_session}}" 2>/dev/null || tmux new-session -d -s "{{_dev_session}}"

# Start Signal Horizon API in its own tmux window
dev-horizon-api: _dev-init
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="signal-horizon-api"
    cmd="cd '{{root}}' && pnpm exec nx run signal-horizon-api:dev"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in existing window" ;;
            *)
                echo "$name: already running ($current)" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started"
    fi

# Start Signal Horizon UI in its own tmux window
dev-horizon-ui: _dev-init
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="signal-horizon-ui"
    cmd="cd '{{root}}' && pnpm exec nx run signal-horizon-ui:dev"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in existing window" ;;
            *)
                echo "$name: already running ($current)" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started"
    fi

# Start Synapse Pingora in its own tmux window
dev-synapse: _dev-init
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="synapse-pingora"
    cmd="cd '{{root}}' && pnpm exec nx run synapse-waf:dev"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in existing window" ;;
            *)
                echo "$name: already running ($current)" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started"
    fi

# Start Signal Horizon API + UI in tmux windows
dev-horizon: dev-horizon-api dev-horizon-ui
    @echo "Signal Horizon:  API → :3100  ·  UI → :5180"
    @echo "Attach: just dev-shell   ·  Status: just dev-status   ·  Stop: just dev-stop"

# Start everything: Signal Horizon + Synapse Pingora in tmux windows
dev: dev-horizon-api dev-horizon-ui dev-synapse
    @echo ""
    @echo "Dev services running in tmux session '{{_dev_session}}':"
    @echo "  Signal Horizon API → :3100"
    @echo "  Signal Horizon UI  → :5180"
    @echo "  Synapse Pingora    → :6190 (proxy) / :6191 (admin)"
    @echo "Attach: just dev-shell   ·  Status: just dev-status   ·  Stop: just dev-stop"

# ─────────────────────────────────────────────────────────────────────────────
# DEMO MODE
# ─────────────────────────────────────────────────────────────────────────────
#
# `just demo` starts Horizon API + UI + a RELEASE-build Synapse WAF with
# --demo, which spins up the procedural traffic simulator documented in
# docs/development/demo-simulator.md. Release build matters: the debug
# binary is a memory hog and gets OOM-killed on laptops after ~30-60
# minutes of continuous simulation, whereas the release build runs
# indefinitely.
#
# First run compiles the release binary (a few minutes). Subsequent runs
# are no-ops since cargo is incremental.
#
# Teardown: `just dev-stop` (same as dev; the demo-synapse recipe reuses
# the `synapse-pingora` tmux window name).

# Build the release synapse-waf binary if it's missing or stale
_demo-build-waf:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{root}}/apps/synapse-pingora"
    if [ ! -x "target/release/synapse-waf" ]; then
        echo "Building release synapse-waf binary (first run only)..."
        cargo build --release --bin synapse-waf
    else
        # Rebuild incrementally; cargo is smart enough to no-op if nothing changed
        cargo build --release --bin synapse-waf
    fi

# Start Synapse WAF release binary in --demo mode (procedural traffic + horizon push)
demo-synapse: _dev-init _demo-build-waf
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="synapse-pingora"
    # Release binary with demo flags and horizon config pointed at localhost
    cmd="cd '{{root}}/apps/synapse-pingora' && SYNAPSE_PRODUCTION=0 SYNAPSE_DEMO=1 SYNAPSE_ADMIN_AUTH_DISABLED=1 RUST_LOG=warn,synapse_waf=info,synapse_waf::simulator=info,synapse_pingora::horizon=info ./target/release/synapse-waf --config config.horizon.yaml --demo"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in --demo mode (release build)" ;;
            *)
                echo "$name: already running ($current) — stop it first with \`just dev-stop-one synapse-pingora\`" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started in --demo mode (release build)"
    fi

# Start the full demo stack: Horizon API + UI + Synapse WAF in --demo mode
demo: dev-horizon-api dev-horizon-ui demo-synapse
    @echo ""
    @echo "Demo stack running in tmux session '{{_dev_session}}':"
    @echo "  Signal Horizon API → http://localhost:3100"
    @echo "  Signal Horizon UI  → http://localhost:5180  ← open this in your browser"
    @echo "  Synapse WAF (demo) → :6190 proxy / :6191 admin"
    @echo ""
    @echo "The Synapse WAF is generating synthetic attacker traffic from"
    @echo "RFC 5737 reserved ranges (198.51.100.x and 203.0.113.99). See"
    @echo "docs/development/demo-simulator.md for the full architecture."
    @echo ""
    @echo "Attach: just dev-shell   ·  Status: just dev-status   ·  Stop: just dev-stop"

# ─────────────────────────────────────────────────────────────────────────────
# FLEET DEMO MODE (3 sensors)
# ─────────────────────────────────────────────────────────────────────────────
#
# `just demo-fleet` starts three synapse-waf processes side by side, each
# with its own sensor identity and its own proxy/admin port pair. All three
# connect to the same horizon hub, so the Fleet Overview page shows them as
# three distinct sensors — useful for demoing horizon's multi-sensor
# capabilities without needing separate machines.
#
# Port allocation:
#   synapse-waf-1: proxy 6190, admin 6191
#   synapse-waf-2: proxy 6290, admin 6291
#   synapse-waf-3: proxy 6390, admin 6391
#
# Sensor identities match the BRIDGE_SENSORS array in the horizon seed at
# apps/signal-horizon/api/prisma/seed/seed-postgres.ts. A fresh seed
# (`pnpm --filter @atlascrew/signal-horizon-api db:seed`) creates all
# three rows; if you wipe the DB, re-seed before launching the fleet.

# Start Synapse WAF sensor #2 (release binary, --demo, sensor identity 2)
demo-synapse-2: _dev-init _demo-build-waf
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="synapse-pingora-2"
    cmd="cd '{{root}}/apps/synapse-pingora' && SYNAPSE_PRODUCTION=0 SYNAPSE_DEMO=1 SYNAPSE_ADMIN_AUTH_DISABLED=1 RUST_LOG=warn,synapse_waf=info,synapse_waf::simulator=info,synapse_pingora::horizon=info ./target/release/synapse-waf --config config.horizon.2.yaml --demo"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in --demo mode" ;;
            *)
                echo "$name: already running ($current)" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started in --demo mode"
    fi

# Start Synapse WAF sensor #3 (release binary, --demo, sensor identity 3)
demo-synapse-3: _dev-init _demo-build-waf
    #!/usr/bin/env bash
    set -euo pipefail
    session="{{_dev_session}}"; name="synapse-pingora-3"
    cmd="cd '{{root}}/apps/synapse-pingora' && SYNAPSE_PRODUCTION=0 SYNAPSE_DEMO=1 SYNAPSE_ADMIN_AUTH_DISABLED=1 RUST_LOG=warn,synapse_waf=info,synapse_waf::simulator=info,synapse_pingora::horizon=info ./target/release/synapse-waf --config config.horizon.3.yaml --demo"
    if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
        current=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' | awk -v n="$name" '$1 == n { print $2; exit }')
        case "$current" in
            zsh|bash|fish|sh)
                tmux send-keys -t "$session:$name" "$cmd" Enter
                echo "$name: restarted in --demo mode" ;;
            *)
                echo "$name: already running ($current)" ;;
        esac
    else
        tmux new-window -d -t "$session" -n "$name"
        tmux send-keys -t "$session:$name" "$cmd" Enter
        echo "$name: started in --demo mode"
    fi

# Start the fleet demo: Horizon + three Synapse WAF instances
demo-fleet: dev-horizon-api dev-horizon-ui demo-synapse demo-synapse-2 demo-synapse-3
    @echo ""
    @echo "Fleet demo running in tmux session '{{_dev_session}}':"
    @echo "  Signal Horizon API → http://localhost:3100"
    @echo "  Signal Horizon UI  → http://localhost:5180  ← open this in your browser"
    @echo "  Synapse WAF #1     → :6190 / :6191  (sensor_id synapse-waf-1)"
    @echo "  Synapse WAF #2     → :6290 / :6291  (sensor_id synapse-waf-2)"
    @echo "  Synapse WAF #3     → :6390 / :6391  (sensor_id synapse-waf-3)"
    @echo ""
    @echo "Navigate to Fleet Overview in the dashboard to see all three sensors."
    @echo "Each sensor runs its own procedural simulator against the same engine"
    @echo "so signals appear tagged per-sensor in horizon's ingestion."
    @echo ""
    @echo "Attach: just dev-shell   ·  Status: just dev-status   ·  Stop: just dev-stop-fleet"

# Stop only the fleet sensor windows (#2 and #3); leaves the main demo alone
dev-stop-fleet:
    -tmux kill-window -t "{{_dev_session}}:synapse-pingora-2" 2>/dev/null
    -tmux kill-window -t "{{_dev_session}}:synapse-pingora-3" 2>/dev/null
    @echo "fleet sensors #2 and #3 stopped"

# Show status of all dev windows (running vs idle vs not running)
dev-status:
    #!/usr/bin/env bash
    session="{{_dev_session}}"
    for name in signal-horizon-api signal-horizon-ui synapse-pingora; do
        if tmux list-windows -t "$session" -F '#W' 2>/dev/null | grep -qx "$name"; then
            cmd=$(tmux list-windows -t "$session" -F '#W #{pane_current_command}' 2>/dev/null | awk -v n="$name" '$1 == n { print $2; exit }')
            case "$cmd" in
                zsh|bash|fish|sh) printf '  %-22s idle (at shell prompt)\n' "$name" ;;
                "")               printf '  %-22s unknown\n' "$name" ;;
                *)                printf '  %-22s running (%s)\n' "$name" "$cmd" ;;
            esac
        else
            printf '  %-22s not running\n' "$name"
        fi
    done

# Tail the last N lines (default 50) from a dev window
dev-tail name n='50':
    tmux capture-pane -t "{{_dev_session}}:{{name}}" -p -S -{{n}}

# Stop all dev windows
dev-stop:
    -tmux kill-window -t "{{_dev_session}}:signal-horizon-api" 2>/dev/null
    -tmux kill-window -t "{{_dev_session}}:signal-horizon-ui"  2>/dev/null
    -tmux kill-window -t "{{_dev_session}}:synapse-pingora"    2>/dev/null
    @echo "all dev windows stopped"

# Stop a single dev window by name
dev-stop-one name:
    tmux kill-window -t "{{_dev_session}}:{{name}}"

# Restart everything (stop + start)
dev-restart: dev-stop dev

# Attach to the dev tmux session
dev-shell:
    tmux attach-session -t "{{_dev_session}}" 2>/dev/null || tmux new-session -s "{{_dev_session}}"

# Kill and recreate the entire tmux session
dev-reset:
    -tmux kill-session -t "{{_dev_session}}" 2>/dev/null
    tmux new-session -d -s "{{_dev_session}}"
    @echo "tmux session '{{_dev_session}}' reset"

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
        -e "s|__SLUG__|{{name}}|g" \
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

# Sync infographic HTML source files to atlascrew.dev/infographics/
infographic-sync:
    #!/usr/bin/env bash
    set -euo pipefail
    src="{{root}}/brand/infographics/html"
    dst="/Users/nick/Developer/Sites/atlascrew.dev/infographics"
    if [[ ! -d "$dst" ]]; then
        echo "error: atlascrew.dev infographics directory not found at $dst" >&2
        exit 1
    fi
    count=0
    for f in "$src"/*.html; do
        [[ "$(basename "$f")" == _* ]] && continue
        cp "$f" "$dst/"
        count=$((count + 1))
    done
    echo "synced $count infographic(s) to $dst"
