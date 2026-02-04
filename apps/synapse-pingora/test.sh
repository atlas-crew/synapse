#!/usr/bin/env bash
#
# Integration test for synapse-pingora
#
# Usage:
#   ./test.sh              # Run tests against running proxy
#   ./test.sh --start      # Start proxy, run tests, stop proxy
#
# Prerequisites:
#   - cargo build --release (if using --start)
#   - A backend server on :8080 (or use nc -l 8080 for testing)
#

set -euo pipefail

# Configuration
PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-6190}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
BINARY="./target/release/synapse-pingora"
TIMEOUT=2

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
TOTAL=0

# ============================================================================
# Helpers
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test a request and check expected status code
# Usage: test_request "name" "path" expected_status
test_request() {
    local name="$1"
    local path="$2"
    local expected="$3"
    local method="${4:-GET}"

    local start_time end_time duration
    start_time=$(date +%s%N)

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" \
        -X "$method" \
        "${PROXY_URL}${path}" 2>/dev/null || echo "000")

    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))  # Convert to ms

    if [[ "$status" == "$expected" ]]; then
        log_pass "$name (${status}) - ${duration}ms"
        return 0
    else
        log_fail "$name - expected ${expected}, got ${status} - ${duration}ms"
        return 1
    fi
}

# Test that a request is blocked (403)
test_blocked() {
    test_request "$1" "$2" "403"
}

# Test that a request passes (200 or 502 if no backend)
test_allowed() {
    local name="$1"
    local path="$2"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" \
        "${PROXY_URL}${path}" 2>/dev/null || echo "000")

    # 200 = backend responded, 502 = no backend but proxy allowed
    if [[ "$status" == "200" ]] || [[ "$status" == "502" ]]; then
        log_pass "$name (${status} - allowed)"
        ((PASSED++))
        ((TOTAL++))
    else
        log_fail "$name - expected 200/502, got ${status}"
        ((FAILED++))
        ((TOTAL++))
    fi
}

wait_for_proxy() {
    local max_attempts=30
    local attempt=0

    log_info "Waiting for proxy to start..."
    while ! curl -s -o /dev/null "${PROXY_URL}/" 2>/dev/null; do
        ((attempt++))
        if [[ $attempt -ge $max_attempts ]]; then
            log_fail "Proxy failed to start after ${max_attempts}s"
            return 1
        fi
        sleep 0.5
    done
    log_info "Proxy is ready"
}

# ============================================================================
# Main
# ============================================================================

main() {
    local start_proxy=false
    local proxy_pid=""

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --start)
                start_proxy=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Start proxy if requested
    if [[ "$start_proxy" == true ]]; then
        if [[ ! -f "$BINARY" ]]; then
            log_info "Building release binary..."
            cargo build --release
        fi

        log_info "Starting synapse-pingora..."
        RUST_LOG=warn "$BINARY" &
        proxy_pid=$!

        # Cleanup on exit
        trap "kill $proxy_pid 2>/dev/null || true" EXIT

        wait_for_proxy || exit 1
    fi

    echo ""
    echo "============================================"
    echo "  Synapse-Pingora Integration Tests"
    echo "============================================"
    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing clean requests (should PASS)..."
    # ────────────────────────────────────────────────────────────────────────

    test_allowed "Simple GET /" "/"
    test_allowed "API endpoint" "/api/users/123"
    test_allowed "With query params" "/api/search?q=hello&page=1"
    test_allowed "Static asset" "/static/main.js"
    test_allowed "POST request" "/api/login" "POST"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing SQL injection (should BLOCK)..."
    # ────────────────────────────────────────────────────────────────────────

    test_blocked "SQLi: OR condition" "/api/users?id=1'+OR+'1'%3D'1"
    test_blocked "SQLi: UNION SELECT" "/api/users?id=1+UNION+SELECT+*+FROM+users"
    test_blocked "SQLi: SELECT FROM" "/api/search?q=';SELECT+password+FROM+users--"
    test_blocked "SQLi: DROP TABLE" "/api/exec?cmd=DROP+TABLE+users"
    test_blocked "SQLi: Comment injection" "/api/users?id=1;--"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing XSS (should BLOCK)..."
    # ────────────────────────────────────────────────────────────────────────

    test_blocked "XSS: script tag" "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    test_blocked "XSS: javascript protocol" "/redirect?url=javascript:alert(1)"
    test_blocked "XSS: event handler" "/comment?text=%3Cdiv+onmouseover%3Dalert(1)%3E"
    test_blocked "XSS: img onerror" "/avatar?url=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
    test_blocked "XSS: svg onload" "/icon?svg=%3Csvg+onload%3Dalert(1)%3E"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing path traversal (should BLOCK)..."
    # ────────────────────────────────────────────────────────────────────────

    test_blocked "Path traversal: ../" "/files/../../../etc/passwd"
    test_blocked "Path traversal: encoded" "/files/%2e%2e%2f%2e%2e%2fetc/passwd"
    test_blocked "Path traversal: Windows" "/download?file=..%5C..%5Cwindows%5Csystem32"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing command injection (should BLOCK)..."
    # ────────────────────────────────────────────────────────────────────────

    test_blocked "Cmd injection: pipe" "/ping?host=127.0.0.1%7Ccat+/etc/passwd"
    test_blocked "Cmd injection: semicolon" "/run?cmd=ls%3B+rm+-rf+/"
    test_blocked "Cmd injection: backtick" "/exec?cmd=%60whoami%60"
    test_blocked "Cmd injection: subshell" "/run?cmd=%24(cat+/etc/passwd)"
    test_blocked "Cmd injection: &&" "/check?host=8.8.8.8+%26%26+cat+/etc/shadow"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    log_info "Testing latency..."
    # ────────────────────────────────────────────────────────────────────────

    local total_time=0
    local iterations=10

    for i in $(seq 1 $iterations); do
        local start_time end_time
        start_time=$(date +%s%N)
        curl -s -o /dev/null --max-time 2 "${PROXY_URL}/api/test" 2>/dev/null || true
        end_time=$(date +%s%N)
        local duration=$(( (end_time - start_time) / 1000000 ))
        total_time=$((total_time + duration))
    done

    local avg_time=$((total_time / iterations))
    log_info "Average request latency (${iterations} requests): ${avg_time}ms"

    echo ""

    # ────────────────────────────────────────────────────────────────────────
    # Summary
    # ────────────────────────────────────────────────────────────────────────

    echo "============================================"
    echo "  Results: ${PASSED}/${TOTAL} passed"
    echo "============================================"
    echo ""

    if [[ $FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}${FAILED} tests failed${NC}"
        exit 1
    fi
}

main "$@"
