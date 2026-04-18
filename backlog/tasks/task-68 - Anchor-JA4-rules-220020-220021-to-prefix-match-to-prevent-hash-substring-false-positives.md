---
id: TASK-68
title: >-
  Anchor JA4 rules 220020/220021 to prefix match to prevent hash-substring false
  positives
status: Done
assignee: []
created_date: '2026-04-12 22:57'
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
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Security auditor finding M1. Rules 220020 and 220021 use `"match": "t10"` and `"match": "t11"` substring matching against JA4 raw strings.

JA4 format: `(q|t)(version 2-char)(sni|nosni)(cipher-count)(ext-count)(alpn)_(cipher hash 12 hex)_(ext hash 12 hex)`

Example: `t13d1516h2_8daaf6152771_e5627efa2ab1`

The `cipher hash` and `ext hash` portions are 12-character lowercase hex substrings (SHA256 truncated). Substrings `t10` and `t11` can legitimately appear inside those hashes — rough probability per 4-char window is ~2/65536 which is low, but across millions of requests the false-positive rate is nonzero. A legitimate TLS 1.3 client whose hash happens to contain `t10` or `t11` would accumulate unnecessary risk.

## Fix

Add a `starts_with` match kind to the engine if not already present, then change the two rules:

```json
// Before:
{"type": "ja4", "match": "t10"}
// After:
{"type": "ja4", "match": {"type": "starts_with", "match": "t10"}}
```

Or use regex anchoring if the engine supports it:

```json
{"type": "ja4", "match": {"type": "regex", "match": "^t10"}}
```

Both rule 220020 and rule 220021 need the anchor.

## Verification

Add a test fabricating a `Ja4Fingerprint` with raw `"t13d1516h2_000t10000000_000000000000"` (modern TLS 1.3 but with "t10" in the cipher hash). Assert rule 220020 does NOT fire. Combined with the existing positive test (raw starts with "t10"), this pins the correct semantics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Rules 220020 and 220021 match only on the JA4 prefix, not anywhere in the raw string
- [x] #2 If the engine supports starts_with match kind, use it; otherwise add one (small engine extension) or use regex with ^ anchor
- [x] #3 New test case: a fabricated JA4 raw string with modern TLS version (t13) but containing 't10' as a substring in the hash portion MUST NOT trigger rule 220020
- [x] #4 Existing positive test cases for rules 220020/220021 still pass
- [x] #5 Rule descriptions in production_rules.json are updated to clarify prefix matching
<!-- AC:END -->

## Final Summary

- Switched production rules 220020 and 220021 from bare-string JA4 substring matching to structured starts_with matching so only the JA4 version prefix can trigger the deprecated TLS rules.
- Updated the rule descriptions to call out the JA4 prefix semantics for auditability in the production ruleset.
- Expanded test_signal_correlation_ja4_rules_fire_on_deprecated_tls to keep the positive prefix cases and add negative regressions for t10/t11 appearing inside the JA4 cipher-hash and ext-hash segments of an otherwise modern TLS 1.3 fingerprint.
- Verification: cargo test --manifest-path apps/synapse-pingora/Cargo.toml --lib waf::engine::tests::test_signal_correlation_ja4_rules_fire_on_deprecated_tls
