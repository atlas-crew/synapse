---
name: synapse-waf-dev
description: Develop, test, and audit the Rust-based Synapse Pingora WAF engine. Use when working in apps/synapse-pingora/, modifying Rust source code, or running Cargo/just recipes for the WAF.
---

# Synapse WAF Development Strategy

This skill provides the procedural knowledge required to develop the high-performance Rust WAF engine safely and idiomatically.

## Environment & Tooling

- **Rust Nightly**: The project requires Rust nightly for certain features. Use `cargo +nightly` if not already set by the toolchain file.
- **Justfile Recipes**: Always use the recipes in the root justfile for common tasks:
  - `just build`: Standard build.
  - `just check-synapse`: Runs clippy and fmt checks.
  - `just test-synapse`: Runs the standard test suite.
  - `just audit-synapse-serial`: Audits tests for mandatory `#[serial]` usage.

## Bundled Utilities

- **`scripts/check_rust_idioms.cjs`**: Scans Rust source code for un-idiomatic patterns discouraged in this project (e.g., `.unwrap()`, `panic!()`, `unsafe` blocks).
  - Usage: `node scripts/check_rust_idioms.cjs <dir_or_file>`

## Testing & Thread Safety

The WAF uses a global `SYNAPSE` singleton for state management. This requires strict synchronization in tests.

- **Mandatory `#[serial]`**: Any test that touches the global `SYNAPSE` state, `DetectionEngine`, or `SynapseProxy` MUST carry the `#[serial]` attribute from the `serial_test` crate.
- **Failure Symptom**: Intermittent test failures or panics during parallel test execution usually indicate a missing `#[serial]` tag.
- **Audit Tool**: Run `just audit-synapse-serial` before committing any new tests.

## Performance & Safety

- **Regex Size Limits**: Use `REGEX_SIZE_LIMIT` (10MB) and `REGEX_DFA_SIZE_LIMIT` for all compiled patterns to prevent ReDoS.
- **Recursion Depth**: Bound all condition evaluation with `MAX_RECURSION_DEPTH` (default 10).
- **Timeouts**: Every analysis pass should be gated by `DEFAULT_EVAL_TIMEOUT` (50ms).

## Workflow

1. **Research**: Identify the module to modify (e.g., `src/waf/engine.rs` for core logic, `src/dlp/` for data loss prevention).
2. **Implementation**: Write idiomatic Rust. Avoid `unsafe` and `unwrap()`—prefer `Result` and `Option` with descriptive error mapping.
3. **Audit**: Run `node scripts/check_rust_idioms.cjs src/` and `just check-synapse`.
4. **Test**: Author unit tests with `#[serial]` where appropriate. Run `just test-synapse`.
5. **Verify**: Use `just test-synapse-heavy` for intensive validation of engine changes.

## Resources

- [Testing & Thread Safety](references/testing.md): Rules for `#[serial]` and singleton management.
- [Module Map](references/modules.md): Overview of the Synapse WAF crate structure.
