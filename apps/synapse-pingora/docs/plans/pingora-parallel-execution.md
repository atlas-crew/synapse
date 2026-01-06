# Pingora Feature Parity — Parallel Execution Plan

**Created**: 2026-01-06
**Status**: Active
**Branch**: `pingora`

## Execution Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PARALLEL EXECUTION ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  IMPLEMENTATION         TESTING              QUALITY GATE                   │
│  ═══════════════       ═══════════          ═══════════                    │
│  rust-pro agents  ──►  test-automator  ──►  code-reviewer                  │
│       ↓                     ↓               performance-engineer            │
│  typescript-pro       rust-pro (tests)      security-auditor               │
│  react-specialist                           (ALL RUN IN PARALLEL)          │
│                                                                             │
│  P0/P1 Issues: Immediate parallel remediation                              │
│  P2-P4 Issues: Document → backlog                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Core Features — Maximum Parallelism

### Workstream 1A: Implementation (Parallel)

**All tasks launch simultaneously:**

| ID | Task | Agent | Dependencies | Output |
|----|------|-------|--------------|--------|
| 1A.1 | Multi-site hostname matching | `rust-pro` | None | `src/vhost.rs` |
| 1A.2 | Site configuration struct | `rust-pro` | None | `src/config.rs` |
| 1A.3 | TLS termination + SNI | `rust-pro` | None | `src/tls.rs` |
| 1A.4 | Health check endpoint | `rust-pro` | None | `src/health.rs` |
| 1A.5 | Per-site WAF application | `rust-pro` | None | `src/site_waf.rs` |

**Merge Point**: 1A.6 integrates all modules into `main.rs` (waits for 1A.1-1A.5)

### Workstream 1B: Testing (Parallel with 1A)

**Starts immediately, does not wait for implementation:**

| ID | Task | Agent | Dependencies | Coverage Target |
|----|------|-------|--------------|-----------------|
| 1B.1 | Vhost matching unit tests | `rust-pro` | None | 95% of `vhost.rs` |
| 1B.2 | Config parsing tests | `rust-pro` | None | 90% of `config.rs` |
| 1B.3 | TLS integration tests | `rust-pro` | None | 85% of `tls.rs` |
| 1B.4 | Health endpoint tests | `rust-pro` | None | 95% of `health.rs` |
| 1B.5 | Site WAF behavior tests | `rust-pro` | None | 90% of `site_waf.rs` |

### Workstream 1C: Quality Gate (Parallel Reviews)

**Triggered after 1A + 1B complete. ALL reviewers run in parallel:**

| ID | Reviewer | Agent | Focus | Output |
|----|----------|-------|-------|--------|
| 1C.1 | Code quality | `code-reviewer` | Rust idioms, error handling, API design | Issues list |
| 1C.2 | Performance | `performance-engineer` | Allocations, async patterns, latency | Benchmark report |
| 1C.3 | Security | `security-auditor` | TLS config, input validation, DoS vectors | Security findings |

**Issue Triage:**
- **P0/P1**: Block → Parallel remediation agents → Re-review
- **P2-P4**: Document in `docs/issues/phase-1-backlog.md` → Continue

---

## Phase 2: Management Features — Maximum Parallelism

### Workstream 2A: Implementation (Parallel)

| ID | Task | Agent | Dependencies | Output |
|----|------|-------|--------------|--------|
| 2A.1 | Prometheus metrics | `rust-pro` | None | `src/metrics.rs` |
| 2A.2 | Config hot-reload (SIGHUP) | `rust-pro` | None | `src/reload.rs` |
| 2A.3 | Access lists (CIDR allow/deny) | `rust-pro` | None | `src/access.rs` |
| 2A.4 | Per-site rate limiting | `rust-pro` | None | `src/ratelimit.rs` |
| 2A.5 | Management HTTP API | `rust-pro` | None | `src/api.rs` |

### Workstream 2B: Testing (Parallel with 2A)

| ID | Task | Agent | Dependencies | Coverage Target |
|----|------|-------|--------------|-----------------|
| 2B.1 | Metrics export tests | `rust-pro` | None | 90% of `metrics.rs` |
| 2B.2 | Reload behavior tests | `rust-pro` | None | 85% of `reload.rs` |
| 2B.3 | Access list unit tests | `rust-pro` | None | 95% of `access.rs` |
| 2B.4 | Rate limit load tests | `rust-pro` | None | 90% of `ratelimit.rs` |
| 2B.5 | API endpoint tests | `rust-pro` | None | 95% of `api.rs` |

### Workstream 2C: Quality Gate (Parallel Reviews)

| ID | Reviewer | Agent | Focus |
|----|----------|-------|-------|
| 2C.1 | Code quality | `code-reviewer` | API ergonomics, config schema |
| 2C.2 | Performance | `performance-engineer` | Rate limiter efficiency, metrics overhead |
| 2C.3 | Security | `security-auditor` | API auth, rate limit bypass, CIDR parsing |

---

## Phase 3: Dashboard Integration — Maximum Parallelism

### Workstream 3A: Implementation (Parallel)

| ID | Task | Agent | Dependencies | Output |
|----|------|-------|--------------|--------|
| 3A.1 | PingoraDashboard.tsx | `react-specialist` | None | Main dashboard component |
| 3A.2 | PingoraServicePanel.tsx | `react-specialist` | None | Service control UI |
| 3A.3 | PingoraConfigPanel.tsx | `react-specialist` | None | Config editor UI |
| 3A.4 | pingora-client.ts | `typescript-pro` | None | API client library |
| 3A.5 | Dual-mode backend detection | `typescript-pro` | None | Auto-switch nginx/pingora |

### Workstream 3B: Testing (Parallel with 3A)

| ID | Task | Agent | Dependencies | Coverage Target |
|----|------|-------|--------------|-----------------|
| 3B.1 | Dashboard component tests | `test-automator` | None | 90% of components |
| 3B.2 | API client unit tests | `typescript-pro` | None | 95% of `pingora-client.ts` |
| 3B.3 | Integration tests (E2E) | `test-automator` | None | Happy path coverage |
| 3B.4 | Dual-mode switching tests | `typescript-pro` | None | Both backends tested |

### Workstream 3C: Quality Gate (Parallel Reviews)

| ID | Reviewer | Agent | Focus |
|----|----------|-------|-------|
| 3C.1 | Code quality | `code-reviewer` | React patterns, TypeScript types |
| 3C.2 | UI/UX | `react-specialist` | Accessibility, responsive design |
| 3C.3 | Security | `security-auditor` | XSS prevention, API call safety |

---

## Phase 4: Advanced Features — Maximum Parallelism

### Workstream 4A: Implementation (Parallel)

| ID | Task | Agent | Dependencies | Output |
|----|------|-------|--------------|--------|
| 4A.1 | DLP body scanning | `rust-pro` | None | `src/dlp.rs` |
| 4A.2 | Request body inspection | `rust-pro` | None | `src/body.rs` |
| 4A.3 | Signal Horizon telemetry | `rust-pro` | None | `src/telemetry.rs` |
| 4A.4 | Custom block pages | `rust-pro` | None | `src/block_page.rs` |
| 4A.5 | Graceful shutdown/draining | `rust-pro` | None | `src/shutdown.rs` |

### Workstream 4B: Testing (Parallel with 4A)

| ID | Task | Agent | Dependencies | Coverage Target |
|----|------|-------|--------------|-----------------|
| 4B.1 | DLP pattern detection tests | `rust-pro` | None | 95% of `dlp.rs` |
| 4B.2 | Body inspection tests | `rust-pro` | None | 90% of `body.rs` |
| 4B.3 | Telemetry integration tests | `rust-pro` | None | 85% of `telemetry.rs` |
| 4B.4 | Block page rendering tests | `rust-pro` | None | 90% of `block_page.rs` |
| 4B.5 | Shutdown behavior tests | `rust-pro` | None | 85% of `shutdown.rs` |

### Workstream 4C: Security Hardening (Parallel)

| ID | Task | Agent | Focus |
|----|------|-------|-------|
| 4C.1 | Fuzzing campaign | `security-auditor` | Input parsing, body handling |
| 4C.2 | Dependency audit | `security-auditor` | `cargo audit`, supply chain |
| 4C.3 | Threat model review | `security-auditor` | Attack surface analysis |
| 4C.4 | Chaos testing | `performance-engineer` | Backend failures, OOM, connection storms |

### Workstream 4D: Quality Gate (Parallel Reviews)

| ID | Reviewer | Agent | Focus |
|----|----------|-------|-------|
| 4D.1 | Code quality | `code-reviewer` | Error handling, panic safety |
| 4D.2 | Performance | `performance-engineer` | Body scanning overhead, telemetry latency |
| 4D.3 | Security | `security-auditor` | Final security sign-off |

---

## Parallel Execution Diagram

```
TIME ──────────────────────────────────────────────────────────────────────►

PHASE 1  ┌─────────────────────────────────────────────────────────────────┐
         │  1A.1 ═══╗                                                      │
         │  1A.2 ═══╬═══► 1A.6 (merge) ═══► 1C.1 ═══╗                      │
         │  1A.3 ═══╣                        1C.2 ═══╬═══► P0/P1 fix ═══►  │
         │  1A.4 ═══╣     ┌─── PARALLEL ───┐ 1C.3 ═══╝         ║          │
         │  1A.5 ═══╝     │                │                   ║          │
         │                │  1B.1 ═════════╪═══════════════════╝          │
         │                │  1B.2 ═════════╪═══════════════════            │
         │  (Tests start  │  1B.3 ═════════╪═══════════════════            │
         │   immediately) │  1B.4 ═════════╪═══════════════════            │
         │                │  1B.5 ═════════╪═══════════════════            │
         │                └────────────────┘                               │
         └─────────────────────────────────────────────────────────────────┘

PHASE 2  ┌─────────────────────────────────────────────────────────────────┐
         │  (Same pattern: Impl ║ Test ║ Review — all parallel)            │
         │  2A.* ═══════════════╬═══════════════════════════════════►      │
         │  2B.* ═══════════════╬═══════════════════════════════════►      │
         │  2C.* ═══════════════╝                                          │
         └─────────────────────────────────────────────────────────────────┘

PHASE 3  ┌─────────────────────────────────────────────────────────────────┐
         │  3A.* (React) ═══════╬═══════════════════════════════════►      │
         │  3B.* (Tests) ═══════╬═══════════════════════════════════►      │
         │  3C.* (Review) ══════╝                                          │
         └─────────────────────────────────────────────────────────────────┘

PHASE 4  ┌─────────────────────────────────────────────────────────────────┐
         │  4A.* (Impl)  ═══════╬═══════════════════════════════════►      │
         │  4B.* (Tests) ═══════╬═══════════════════════════════════►      │
         │  4C.* (Security) ════╬═══════════════════════════════════►      │
         │  4D.* (Review) ══════╝                                          │
         └─────────────────────────────────────────────────────────────────┘

LEGEND:  ═══  Parallel execution     ╬  Sync point     ►  Completion
```

---

## Agent Assignment Summary

| Agent | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Total Tasks |
|-------|---------|---------|---------|---------|-------------|
| `rust-pro` | 10 | 10 | 0 | 10 | **30** |
| `typescript-pro` | 0 | 0 | 3 | 0 | **3** |
| `react-specialist` | 0 | 0 | 4 | 0 | **4** |
| `test-automator` | 0 | 0 | 2 | 0 | **2** |
| `code-reviewer` | 1 | 1 | 1 | 1 | **4** |
| `performance-engineer` | 1 | 1 | 0 | 2 | **4** |
| `security-auditor` | 1 | 1 | 1 | 4 | **7** |

---

## Issue Triage Protocol

```
┌─────────────────────────────────────────────────────────────────┐
│                    QUALITY GATE ISSUE FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Review Complete ──► Issues Found?                               │
│                           │                                      │
│                     ┌─────┴─────┐                                │
│                     │           │                                │
│                   P0/P1       P2-P4                              │
│                     │           │                                │
│              ┌──────┴──────┐    │                                │
│              │ PARALLEL    │    ▼                                │
│              │ REMEDIATION │  Document in                        │
│              │   AGENTS    │  backlog.md                         │
│              └──────┬──────┘    │                                │
│                     │           │                                │
│                     ▼           │                                │
│               Re-review ◄───────┘                                │
│                     │                                            │
│                     ▼                                            │
│               Phase Complete                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**P0 (Critical)**: Security vulnerabilities, data corruption, crashes
**P1 (Important)**: Incorrect behavior, performance regression >20%, API breaks
**P2 (Medium)**: Code style, minor refactors, non-critical warnings
**P3 (Low)**: Documentation gaps, nice-to-have improvements
**P4 (Backlog)**: Future enhancements, tech debt notes

---

## Coverage Requirements

| Module Type | Minimum | Target |
|-------------|---------|--------|
| Core logic (WAF, vhost) | 90% | 95% |
| Configuration parsing | 85% | 90% |
| API endpoints | 90% | 95% |
| TLS/Security | 85% | 90% |
| UI components | 85% | 90% |
| **Overall** | **85%** | **95%** |

---

## Dependency Graph (Minimal Blocking)

```
PHASE 1                PHASE 2                PHASE 3                PHASE 4
═══════                ═══════                ═══════                ═══════

1A.1 ──┐
1A.2 ──┼──► 1A.6 ─────► 2A.5 (API) ─────────► 3A.4 (client) ──┐
1A.3 ──┤        │                                              │
1A.4 ──┤        │       2A.1 ──┐                               │
1A.5 ──┘        │       2A.2 ──┼──► Phase 2 ──► 3A.* (UI) ─────┤
                │       2A.3 ──┤    Complete                    │
                │       2A.4 ──┘                                │
                │                                               │
                └───────────────────────────────────────────────┴──► 4A.*

CRITICAL PATH: 1A.6 → 2A.5 → 3A.4 → Phase 4 start
```

**Key insight**: Most tasks have NO dependencies. Only the integration/merge points block.
