---
id: TASK-103.2
title: Scaffold Helm chart workspace and validation tooling
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
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
    backlog/docs/deployment/kubernetes-helm-packaging-plan/doc-1 -
    Kubernetes-and-Helm-packaging-plan.md
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
- [ ] #1 Repository includes charts/synapse, charts/synapse-fleet, and charts/synapse-waf with valid Chart.yaml files
- [ ] #2 helm lint and helm template commands are documented and runnable locally
- [ ] #3 Chart validation is wired into package scripts, just recipes, or CI in a way that fits existing repo tooling
<!-- AC:END -->
