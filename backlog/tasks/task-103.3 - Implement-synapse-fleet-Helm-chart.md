---
id: TASK-103.3
title: Implement synapse-fleet Helm chart
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
labels:
  - feature
  - helm
  - kubernetes
  - signal-horizon-api
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.2
references:
  - apps/signal-horizon/Dockerfile
  - docs/dockerhub-synapse-fleet.md
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
Build the first real application chart for Synapse Fleet. It should translate the existing Docker/Render deployment model into Kubernetes while preserving long-running WebSocket support for sensor ingestion and dashboard fanout.

Keep ClickHouse optional and Redis recommended/configurable. Admin and metrics secrets should be handled through existingSecret-style values for production installs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Chart deploys the Fleet API with configurable image, env, secrets, service, resources, probes, and pod security settings
- [ ] #2 Chart supports required PostgreSQL configuration through existing secret refs or provided values, without enabling bundled production database defaults
- [ ] #3 Chart includes migration Job or hook behavior for Prisma deploy migrations with documented failure/rollback expectations
- [ ] #4 Chart supports dashboard/UI runtime config or static-service integration for REST and WebSocket URLs
<!-- AC:END -->
