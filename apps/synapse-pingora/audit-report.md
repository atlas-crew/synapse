# Codebase Audit Report

**Generated:** 2026-02-10T14:48:10Z
**Project:** synapse-pingora

## Clippy Analysis

| Category | Count |
|----------|-------|
| Warnings | 1 |
| Errors | 1 |

<details>
<summary>Clippy Output (click to expand)</summary>

```
    Checking synapse-pingora v0.1.0 (/Users/nferguson/Developer/labs/apps/synapse-pingora)
src/metrics.rs:8:39: warning: unused import: `CrawlerStatsSnapshot`
src/waf/synapse.rs:146:21: error[E0599]: no method named `rule_count` found for struct `waf::engine::Engine` in the current scope: method not found in `waf::engine::Engine`
src/tui.rs:703:36: error[E0609]: no field `metrics` on type `&mut tui::TuiApp`: unknown field
src/tui.rs:720:34: error[E0609]: no field `metrics` on type `&mut tui::TuiApp`: unknown field
src/tui.rs:742:36: error[E0609]: no field `metrics` on type `&mut tui::TuiApp`: unknown field
src/tui.rs:759:34: error[E0609]: no field `metrics` on type `&mut tui::TuiApp`: unknown field
src/tui.rs:785:24: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:794:28: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:827:32: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:828:28: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:833:61: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:1060:27: error[E0609]: no field `metrics` on type `&tui::TuiApp`: unknown field
src/tui.rs:1075:53: error[E0282]: type annotations needed
warning: `synapse-pingora` (lib) generated 1 warning
error: could not compile `synapse-pingora` (lib) due to 12 previous errors; 1 warning emitted
```
</details>

## Test Results

| Status | Count |
|--------|-------|
| Passed | 0 |
| Failed | 0 |
| Ignored | 0 |

## Summary

⚠️ **2 total issues** require attention.

Priority:
1. Fix compilation errors (1)
2. Fix test failures (0)
3. Address clippy warnings (1)

---
*Run `./hooks/issue-generator.sh audit-report.md` to create issue files.*
