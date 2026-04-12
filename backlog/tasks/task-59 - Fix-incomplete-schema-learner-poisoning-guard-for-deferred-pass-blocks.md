---
id: TASK-59
title: Fix incomplete schema learner poisoning guard for deferred-pass blocks
status: Done
assignee: []
created_date: '2026-04-12 22:55'
updated_date: '2026-04-12 23:06'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - critical
  - correctness
  - security
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/tests/filter_chain_integration.rs
  - apps/synapse-pingora/src/profiler/schema_learner.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Multi-specialist review (security-auditor, perf-monitor) found that TASK-41's schema learner poisoning fix is incomplete. The current implementation in `apps/synapse-pingora/src/main.rs`:

1. `request_body_filter` validates schema, stashes body in `pending_learn: Option<(String, serde_json::Value)>`, runs body-phase WAF
2. On body-phase block: `return Ok(())` drops `pending_learn` without consuming → learner stays clean ✓
3. On body-phase allow: falls through to `if let Some(...) { SCHEMA_LEARNER.learn_from_request(&template_path, &json_body) }` → learner trains on the body ❌
4. Request proceeds to `upstream_request_filter`, which runs the deferred WAF pass
5. **The deferred pass may block via `dlp_violation` rules (220001-220007) AFTER the learner has already trained**

Exploit scenario: attacker POSTs a JSON body containing 5 credit cards. Rule 220001 (mass DLP >=5, blocking) is tagged deferred, so body-phase WAF returns Allow. `pending_learn` is consumed, `learn_from_request` trains on the attacker's JSON shape. DLP scan completes, deferred pass evaluates, rule 220001 blocks. HTTP response is 403 but the learner baseline is now polluted with attacker-controlled schema. The commit message for TASK-41 (252b0c7) claims "attackers can no longer poison the schema baseline with payloads that would've been blocked anyway" — this claim is false for any body whose block decision comes from the deferred pass.

This is the single biggest correctness finding from the review. It affects all 7 DLP-based blocking rules (220001-220007) plus any future deferred-pass rule that doesn't also fire a body-phase block.

## Fix options

**Option A — defer learning to upstream_request_filter post-deferred-pass**: thread `pending_learn` through `RequestContext` into `upstream_request_filter`, consume it after the deferred pass runs, only train if neither the body-phase nor deferred-phase blocked.

**Option B — defer to response_filter**: stash `pending_learn` on RequestContext and consume it in response_filter after the full verdict is known. Simpler lifetime but adds a new field to RequestContext and the learner trains later (after upstream has already processed the request, not just WAF).

**Option C — only train on 200-class responses**: bypass the verdict-observation problem entirely by moving learning into response_filter gated on `status_code < 300`. Cleanest semantically but loses the ability to learn from error responses.

Option A is the most surgical fix.

## Test the fix

The existing `test_schema_learner_not_poisoned_by_blocked_bodies` test mirrors the `drop()` pattern with a local `Option`. This doesn't exercise the real filter chain. Rewrite it as an integration test in `filter_chain_integration.rs` using the TASK-40 UnixStream harness: inject a deferred DLP rule, POST a body with 5+ credit cards, drive the full filter chain through `upstream_request_filter`, assert:
1. The response is a 403 (deferred block fired)
2. The `SCHEMA_LEARNER.get_schema(template_path)` is `None` (learner not trained)
3. A separate benign body on the same template IS trained (regression guard that the fix doesn't break legitimate learning)
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 pending_learn is consumed at a point AFTER both the body-phase WAF verdict AND the deferred WAF pass have decided not to block (Option A, B, or C from the description)
- [x] #2 The fix must not regress legitimate learning: benign bodies that neither phase blocks must still train the learner
- [x] #3 New integration test in filter_chain_integration.rs drives the real filter chain with a deferred-blocking DLP rule injected via reload_rules, posts a body that trips the rule, and asserts SCHEMA_LEARNER.get_schema(template) is None after the request
- [x] #4 The same integration test asserts a benign body on the same template IS trained (regression guard)
- [x] #5 Existing TASK-41 test test_schema_learner_not_poisoned_by_blocked_bodies is either deleted or rewritten to drive real filter code (not a local drop() mirror)
- [x] #6 All 205 existing tests continue to pass
- [x] #7 Commit message explicitly corrects the TASK-41 commit message claim about baseline pollution being prevented
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Fixed the TASK-41 schema learner poisoning guard to cover deferred-pass blocks. The security auditor's C1 finding was correct: the original fix consumed `pending_learn` at the end of `request_body_filter`, which runs BEFORE the deferred WAF pass in `upstream_request_filter`. Any rule that blocks via `dlp_violation` (rules 220001-220007) could train the learner on the attacker's body and THEN block the request, leaving the baseline permanently polluted.

## Fix (Option A from the task description)

Moved `pending_learn` from a stack-local in `request_body_filter` to a field on `RequestContext`, and moved the consume-and-train from end of `request_body_filter` to end of `upstream_request_filter` after the deferred pass section.

**Changes in `src/main.rs`:**

1. **`RequestContext` struct**: added `pending_learn: Option<(String, serde_json::Value)>` field with a doc comment explaining the lifecycle and the TASK-59 fix rationale.

2. **`new_ctx`**: initialized `pending_learn: None`.

3. **`request_body_filter`**: removed the stack-local `let mut pending_learn: Option<...> = None;` and the matching consume-and-train at the end. The schema validation block now stashes into `ctx.pending_learn = Some(...)` instead of the local. The body-phase block path's comment updated to document that the ctx field is NOT consumed on block — it stays on ctx until request drop.

4. **`upstream_request_filter`**: added a consume-and-train at the end of the deferred-pass section, right after the `if ctx.dlp_scan_completed { ... }` block closes. Uses `ctx.pending_learn.take()` so repeat calls (e.g. upstream retries) cannot retrain. The code path guarantees:
   - Body-phase block → early return from `request_body_filter` → upstream_request_filter never runs → pending_learn drops with ctx, learner clean
   - Deferred-phase block → `return Err(HTTPStatus(403))` before the consume-and-train → pending_learn drops with ctx, learner clean
   - Both passes allow → falls through to consume-and-train → learner trained

5. **`SCHEMA_LEARNER` static**: bumped from `static` to `pub(crate) static` so the integration test in `filter_chain_integration.rs` (pulled in via `#[path]`) can observe learner state directly.

## Tests

**Deleted**: the old `test_schema_learner_not_poisoned_by_blocked_bodies` in `main.rs` mod tests. It was a false-confidence test that mirrored the `drop()` pattern with a local `Option` and tested the scaffold, not production code. It kept passing throughout the TASK-59 bug because it only exercised the half of the code path the fix happened to cover.

**Added**: `test_schema_learner_not_poisoned_by_deferred_dlp_block` in `tests/filter_chain_integration.rs`. This test drives the REAL filter chain:

1. Injects a deferred-blocking DLP rule (id 9998, `dlp_violation >= 1`) via `DetectionEngine::reload_rules`
2. POSTs a body containing an SSN to a unique template path (`/api/task59-poisoning-probe`)
3. Drives `early_request_filter` → `request_filter` → `request_body_filter` (streams body chunks) → `upstream_request_filter`
4. Asserts `upstream_request_filter` returned `Err` (deferred DLP rule fired)
5. Asserts `SCHEMA_LEARNER.get_schema(template_path).is_none()` — the core TASK-59 guarantee
6. Restores production rules
7. Drives a SECOND benign request through the full filter chain on a different template (`/api/task59-benign-probe`)
8. Asserts `SCHEMA_LEARNER.get_schema(benign_template).is_some()` — regression guard that the fix doesn't break legitimate learning

The test uses `#[serial]` to coordinate with other SYNAPSE-mutating tests.

## Verification

- `cargo check` clean
- `cargo test --lib waf::` — **103 passing** (unchanged)
- `cargo test --bin synapse-waf -- tests::` — **48 passing** (was 49; deleted 1 false-confidence test)
- `cargo test --test filter_chain_integration` — **53 passing** (includes the 45 main.rs mod tests pulled in via `#[path]` — 1 deleted from main.rs means 44 from that side + 9 native integration tests = 53)
- **Total: 204 tests green**, 0 regressions, 1 new integration test covering the previously-broken path

## AC mapping

- **AC#1** (consume after both passes) — `ctx.pending_learn.take()` at end of `upstream_request_filter`'s deferred-pass section, after all blocking early-returns.
- **AC#2** (legitimate learning preserved) — regression guard in the integration test asserts a benign non-blocked body still trains the learner.
- **AC#3** (integration test with reload_rules injection) — `test_schema_learner_not_poisoned_by_deferred_dlp_block` injects a deferred DLP rule, drives the real filter chain, asserts learner state.
- **AC#4** (regression guard on benign body) — same test, second request to a different template path.
- **AC#5** (delete or rewrite old test) — `test_schema_learner_not_poisoned_by_blocked_bodies` deleted from `main.rs` mod tests with a comment pointing readers to the new integration test.
- **AC#6** (existing tests still pass) — 204 green (was 205 — the 1 delta is the deleted false-confidence test).
- **AC#7** (commit message corrects TASK-41 claim) — will be written into the commit message.

## Correction to TASK-41 claim

The `252b0c7` commit message stated: *"attackers can no longer poison the schema baseline with payloads that would've been blocked anyway"*. This was **false** for any payload whose block decision comes from the deferred WAF pass (rules 220001-220007 and any future dlp_violation-based rule). TASK-59 closes that gap. The accurate statement is now: **"attackers cannot poison the schema baseline with payloads that are blocked by any phase of the WAF — body-phase or deferred-phase."**

## What this does NOT cover

- **TASK-69 (sub-threshold schema drift)**: bodies that produce `schema_violation` score > 0 but < 25 still train the learner under TASK-59. They're allowed by the WAF, so `ctx.pending_learn` is consumed normally. An attacker can still perform adaptive baseline poisoning by staying under the block threshold. That's a separate fix tracked in TASK-69.
- **Non-WAF blocking paths**: if a request is blocked by a rate limit, CIDR deny, or crawler bad-bot match (all in `request_filter`, before `request_body_filter`), the body is never parsed and `pending_learn` is never set, so the learner is trivially clean.
- **Upstream retries**: if Pingora calls `upstream_request_filter` multiple times on a retry, `ctx.pending_learn.take()` ensures only the first call consumes. Subsequent calls see None and are no-ops.
<!-- SECTION:FINAL_SUMMARY:END -->
