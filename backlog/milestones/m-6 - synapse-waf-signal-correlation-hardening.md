---
id: m-6
title: "Synapse WAF Signal Correlation Hardening"
---

## Description

Follow-up work from the multi-perspective review of the WAF deferred-pass signal correlation change, which introduced JA4/JA4H, DLP, and schema-validation match kinds and a deferred post-DLP rule-evaluation pass in apps/synapse-pingora. Tracks defects, test-quality gaps, operational verification, and future-work items that should land before or shortly after the signal-correlation change merges. Scope: the waf/ module and the request_body_filter / upstream_request_filter sites in main.rs.
