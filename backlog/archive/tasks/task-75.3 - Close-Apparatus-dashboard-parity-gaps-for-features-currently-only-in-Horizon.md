---
id: TASK-75.3
title: Close Apparatus dashboard parity gaps for features currently only in Horizon
status: To Do
assignee: []
created_date: '2026-04-17 03:40'
labels:
  - apparatus
  - federation
  - cross-repo
milestone: m-7
dependencies:
  - TASK-75.1
parent_task_id: TASK-75
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Using the audit output, close any gaps where Horizon's Active Defense UI exposes functionality the Apparatus dashboard does not. This must complete before Horizon's write-side pages are removed, otherwise operators lose capability.

Gap resolution per feature is one of:
- Build the equivalent in Apparatus dashboard, or
- Accept written "not needed in Apparatus" decision (attached to the audit plan)

Any "build in Apparatus" work happens in the Apparatus repo at `/Users/nick/Developer/Apparatus/`, not in the Edge Protection repo.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every feature flagged as 'gap' in docs/development/plans/active-defense-federation.md has a corresponding Apparatus dashboard implementation OR a documented 'not needed' decision
- [ ] #2 Apparatus dashboard gap-fill features have tests passing in the Apparatus repo
- [ ] #3 Screenshots/notes appended to the federation plan confirming parity
- [ ] #4 Federation plan updated with 'parity confirmed' checkbox per feature
<!-- AC:END -->
