---
id: TASK-103.1
title: Define Helm chart structure and values contract
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
labels:
  - feature
  - helm
  - kubernetes
  - deployment
milestone: Kubernetes + Helm Packaging
dependencies: []
references:
  - docs/architecture/platform-map.md
  - render.yaml
documentation:
  - >-
    backlog/docs/deployment/kubernetes-helm-packaging-plan/doc-1 -
    Kubernetes-and-Helm-packaging-plan.md
parent_task_id: TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create the detailed implementation contract before chart scaffolding begins. This task should turn the packaging plan into concrete chart boundaries, values keys, default behaviors, and compatibility expectations for Fleet API/UI, WAF sensors, and supporting services.

Call out migration-job behavior, WebSocket/Ingress assumptions, public UI URL wiring, and how existing Docker/Render deployment assumptions map into Kubernetes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Chart boundaries are documented for synapse-fleet, synapse-waf, and the umbrella synapse chart
- [ ] #2 values.yaml contract covers images, env/secrets, ingress, services, WAF config, resources, security context, metrics, and dependency toggles
- [ ] #3 Production defaults prefer externally managed PostgreSQL and Redis, with demo/dev dependency profiles documented separately
<!-- AC:END -->
