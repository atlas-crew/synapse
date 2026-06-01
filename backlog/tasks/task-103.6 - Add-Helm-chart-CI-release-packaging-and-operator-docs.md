---
id: TASK-103.6
title: 'Add Helm chart CI, release packaging, and operator docs'
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
updated_date: '2026-06-01 19:06'
labels:
  - documentation
  - helm
  - kubernetes
  - ci
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.5
references:
  - site/getting-started/installation.md
  - site/reference/synapse-features.md
  - package.json
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Close the Helm packaging milestone with the validation, release, and docs path operators need. The implementation should make chart regressions visible in CI and give users a clear install path for Kubernetes without losing the existing hosted/static UI story.

If chart publishing is not ready to automate, document the chosen release channel and file a follow-up for automation rather than leaving the process implicit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 CI lints, templates, and packages all Helm charts on pull requests
- [ ] #2 Release workflow publishes chart artifacts to the selected channel or documents the manual release command
- [ ] #3 Operator docs cover install, upgrade, rollback, migrations, secrets, ingress/WebSocket notes, metrics, and production dependency guidance
- [ ] #4 Docs describe where Vercel/static UI hosting fits when the Kubernetes cluster hosts the Fleet API
<!-- AC:END -->
