---
id: TASK-62
title: >-
  Scope or downgrade rule 220005 (JWT in body) to prevent OAuth/OIDC false
  positives
status: Done
assignee: []
created_date: '2026-04-12 22:56'
updated_date: '2026-04-13 01:14'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - rules
  - false-positive-risk
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/production_rules.json
  - apps/synapse-pingora/src/waf/engine.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Security auditor flagged rule 220005 (`dlp_violation field=jwt >= 1`, risk=70, blocking=true) as high false-positive risk for real OAuth/OIDC/SSO traffic.

Legitimate traffic that puts JWTs in request bodies:
- OAuth2 refresh-token flow: `grant_type=refresh_token&refresh_token=<JWT>`
- OIDC back-channel logout: token POSTed as `logout_token`
- Apple Sign In: `id_token` in form POST body
- Google OAuth `id_token` form-POST callbacks
- SAML-bearer token exchange endpoints
- Webhook signature validation payloads
- Any `POST /auth/refresh` or `/oauth/token` endpoint

Deploying this rule as-is to any application with OAuth would brick first-party authentication.

## Fix options (pick one)

**Option A — downgrade to non-blocking risk contribution**: change `blocking: true` → `blocking: false`, keep risk at 30-40. Logs the signal for audit without blocking traffic. This is the safest default.

**Option B — path scoping via rule condition**: add a negative path match condition `not(path starts_with /auth/)` AND `not(path starts_with /oauth/)` AND `not(path starts_with /.well-known/)`. Requires the rule DSL to support AND composition with deferred match kinds — verify this works with the current `condition_is_deferred` tagging.

**Option C — correlation requirement**: only block if JWT in body co-occurs with another signal (high entity risk, suspicious fingerprint, etc). Requires engine-level support for cross-match-kind correlation — more work.

**Option A is the recommended default** for this task. File Option B/C as future work if a real deployment hits the FP pain and wants more precision.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Rule 220005 is either downgraded to non-blocking (risk 30-40, blocking=false) OR scoped to exclude /auth/, /oauth/, /.well-known/ and other OAuth callback paths
- [x] #2 The rule's test case in test_signal_correlation_dlp_rules_fire_on_intended_triggers is updated to reflect the new behavior
- [x] #3 A negative test case is added: a POST to /oauth/token with a JWT in the body MUST NOT be blocked by 220005
- [x] #4 The production_rules.json change documents the calibration decision in a comment field on the rule
- [x] #5 All 205 tests continue to pass
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Downgraded rule 220005 (JWT in request body) from a blocking rule to a non-blocking risk contribution. This closes security auditor finding H1 (OAuth/OIDC false-positive risk).

## Fix

**Option A (from task description)**: changed the rule in `apps/synapse-pingora/src/production_rules.json`:

| Field | Before | After |
|---|---|---|
| `blocking` | `true` | `false` |
| `risk` | `70.0` | `30.0` |
| `description` | "...body placement indicates misuse" | "non-blocking signal — JWTs can legitimately appear in OAuth/OIDC form-POST flows; surfaces in entity risk for correlation, does not block outright — see TASK-62 rationale" |

The rule's match condition is unchanged (`dlp_violation field=jwt >= 1`). It still FIRES on any JWT in a request body and contributes 30 to the entity risk score. It just no longer produces a hard 403 on its own.

## Why Option A (non-blocking) over Option B (path scoping)

Option B would have required an `and(dlp_violation, not(starts_with "/auth/"))` rule construction. The engine's `condition_is_deferred` walker would need to recurse through the `and` wrapper to tag the rule as deferred (TASK-38 confirmed this works for boolean wrappers, so path scoping IS technically feasible). However:

1. Path scoping is an incomplete defense — any deployment with OAuth at a non-`/auth/` path (e.g., `/api/v1/token`, `/accounts/login`, `/sso/callback`) still false-positives.
2. Downgrading preserves the signal for correlation and observability without taking the risk of blocking legitimate traffic.
3. Deployments that genuinely want JWT-in-body blocking can re-enable it via a follow-up task once they've audited their specific path layout. Non-blocking is the safer default for the embedded ruleset that ships to every deployment.

Filed as implicit future work: if a deployment wants path-scoped blocking, construct it as a separate rule (e.g., `{"id": 220005b, "matches": [{"type": "boolean", "op": "and", "match": [{"type": "uri", "match": {"type": "regex", "match": "^/api/"}}, {"type": "dlp_violation", "field": "jwt", "match": 1}]}]}`) rather than editing 220005.

## Tests

**New test: `test_rule_220005_jwt_in_body_is_non_blocking_after_task_62`** in `apps/synapse-pingora/src/waf/engine.rs`. Asserts:

1. The rule still fires on a JWT DLP match (`verdict.matched_rules.contains(&220005)`) — detection still surfaces for observability and entity risk accumulation.
2. **The verdict is `Action::Allow`, not `Action::Block`** — the core TASK-62 guarantee. If any future refactor re-enables blocking on 220005, this assertion fails with a clear pointer to the OAuth/OIDC false-positive concern.
3. The risk score is at least 30 (the current TASK-62 calibration). If someone tunes the risk down, this fails.

The test uses a fabricated request to `/oauth/token` with a single JWT DLP match — the exact scenario the downgrade protects against.

**Existing test update**: `test_signal_correlation_dlp_rules_fire_on_intended_triggers` already uses `matched_rules.contains(&220005)` which passes for non-blocking rules too (since `matched_rules` includes all fired rules regardless of action). Added a comment pointing readers to the new non-blocking test.

**Compat test**: `test_production_rules_load_into_current_engine` continues to pass with 248 rules.

## Verification

- `cargo check` clean
- `cargo test --lib waf::` — **104 passing** (was 103, +1 new)
- `cargo test --bin synapse-waf -- tests::` — 50 passing (unchanged)
- `cargo test --test filter_chain_integration` — 55 passing (unchanged)
- **Total: 209 tests green, 0 regressions**

## AC mapping

- **AC#1** (downgraded to non-blocking): ✓ `blocking: false`, risk 30.
- **AC#2** (existing test updated): ✓ comment added to `test_signal_correlation_dlp_rules_fire_on_intended_triggers`'s 220005 section pointing at the new non-blocking test.
- **AC#3** (negative test: /oauth/token with JWT must not be blocked): ✓ `test_rule_220005_jwt_in_body_is_non_blocking_after_task_62` constructs a request to `/oauth/token` with a JWT match and asserts `verdict.action == Action::Allow`.
- **AC#4** (rule description documents calibration): ✓ the description field now mentions OAuth/OIDC legitimacy, the non-blocking signal role, and references TASK-62.
- **AC#5** (all tests pass): ✓ 209 green.

## Follow-ups (not filed as tasks, implicit future work)

1. If a customer deployment wants JWT-in-body blocking for specific non-OAuth paths, add a sibling rule 220005b with path scoping rather than editing 220005.
2. Consider a correlation-based variant: block only when JWT-in-body co-occurs with high entity risk or a suspicious fingerprint. Requires engine-level support for cross-match-kind correlation which doesn't exist yet.
3. Apply the same "detection + risk contribution, not block" pattern to rule 220001 (mass DLP leak) — that's TASK-63.
<!-- SECTION:FINAL_SUMMARY:END -->
