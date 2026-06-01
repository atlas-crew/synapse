---
id: TASK-103.5
title: Compose umbrella synapse chart and demo values
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
updated_date: '2026-06-01 19:06'
labels:
  - feature
  - helm
  - kubernetes
  - deployment
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.3
  - TASK-103.4
references:
  - docs/architecture/platform-map.md
  - docs/dockerhub-synapse-fleet.md
  - docs/dockerhub-synapse-waf.md
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create the top-level operator experience after the component charts exist. This chart should let users install a complete Synapse stack while still allowing them to install Fleet or WAF separately.

Include values examples for demo and production-shaped installs. Treat bundled dependencies as convenience profiles rather than production defaults.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Umbrella chart composes synapse-fleet and synapse-waf with sane default wiring between Fleet and WAF telemetry
- [ ] #2 Demo values can install a working non-production stack with explicit dependency choices
- [ ] #3 Production values example uses externally managed PostgreSQL/Redis and does not expose admin surfaces publicly by default
- [ ] #4 helm template output is validated for default, demo, and production-example values
<!-- AC:END -->
