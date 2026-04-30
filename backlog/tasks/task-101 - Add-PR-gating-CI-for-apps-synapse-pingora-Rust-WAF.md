---
id: TASK-101
title: Add PR-gating CI for apps/synapse-pingora (Rust WAF)
status: To Do
assignee: []
created_date: '2026-04-30 08:23'
labels:
  - ci
  - synapse-waf
  - rust
dependencies: []
references:
  - .github/workflows/publish-synapse.yml
  - .github/workflows/signal-horizon-quality.yml
  - apps/synapse-pingora/justfile
  - justfile
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rust quality checks for `apps/synapse-pingora` (clippy, rustfmt, cargo test) only run on `synapse-waf-v*` tag pushes via `publish-synapse.yml`. PRs to main that touch the WAF do not get gated, so Rust regressions ship unflagged until release time. Add a new `synapse-waf-quality.yml` workflow that mirrors signal-horizon-quality.yml but for Rust: triggers on PR + push to main with appropriate path filters, runs `just check-synapse` (clippy + rustfmt --check) and `just test-synapse` (cargo test). The justfile recipes already exist. Use `dtolnay/rust-toolchain@nightly` and `Swatinem/rust-cache@v2` to match the existing publish workflow. Concurrency-cancel old runs to keep CI minutes in check.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 New workflow .github/workflows/synapse-waf-quality.yml gates PRs touching apps/synapse-pingora/** or its build inputs
- [ ] #2 Workflow runs cargo fmt --check, cargo clippy with warnings-as-errors policy aligned with publish-synapse.yml, and cargo test --lib --bins
- [ ] #3 Uses Swatinem/rust-cache for cargo cache reuse and concurrency.cancel-in-progress like sibling workflows
- [ ] #4 Required check status reported back to the PR — passing builds gate merge
<!-- AC:END -->
