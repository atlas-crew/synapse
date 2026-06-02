---
id: TASK-103.2
title: Scaffold Helm chart workspace and validation tooling
status: Done
assignee:
  - '@myself'
created_date: '2026-06-01 18:54'
updated_date: '2026-06-02 19:20'
labels:
  - feature
  - helm
  - kubernetes
  - ci
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.1
references:
  - package.json
  - pnpm-workspace.yaml
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add the initial chart directory structure and the smallest useful validation loop. This slice should avoid implementing all templates at once; it should make the chart workspace real, repeatable, and easy for later tasks to fill in.

Prefer standard Helm chart conventions and keep generated metadata stable so later chart tasks produce narrow diffs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Repository includes charts/synapse, charts/synapse-fleet, and charts/synapse-waf with valid Chart.yaml files
- [x] #2 helm lint and helm template commands are documented and runnable locally
- [x] #3 Chart validation is wired into package scripts, just recipes, or CI in a way that fits existing repo tooling
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Create charts/synapse-fleet, charts/synapse-waf, and charts/synapse with stable Chart.yaml, values.yaml, and starter templates.
2. Add a repo-local validation recipe for helm lint/template so the scaffold is runnable without memorizing command strings.
3. Wire the root tooling/docs so later Helm tasks inherit the same validation path, then verify the new charts render cleanly with the documented profiles.
4. Mark the task complete, capture the validation evidence, and commit atomically with cortex git commit.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Scaffolded the Synapse Helm workspace with umbrella, fleet, and WAF charts; added repo-local helm lint/template/validate recipes; documented the workflow; wired helm-validate into CI; and verified the charts render cleanly, including enable/disable toggle assertions and lockfile-safe dependency handling.
<!-- SECTION:FINAL_SUMMARY:END -->
