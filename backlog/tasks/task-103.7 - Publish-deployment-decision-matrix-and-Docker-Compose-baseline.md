---
id: TASK-103.7
title: Publish deployment decision matrix and Docker Compose baseline
status: To Do
assignee: []
created_date: '2026-06-01 19:06'
labels:
  - documentation
  - deployment
  - docker
  - compose
  - vps
milestone: Kubernetes + Helm Packaging
dependencies: []
references:
  - README.md
  - docs/dockerhub-synapse-fleet.md
  - docs/dockerhub-synapse-waf.md
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create the top-level deployment guidance that helps operators choose the right packaging path before following provider-specific steps. This should preserve Docker Compose/VPS as the portable baseline and make clear which methods can host Fleet API, WAF, UI, and backing stores.

Use the existing Docker Hub docs and README as source material, and call out where WebSockets, migrations, and admin/metrics exposure change per hosting method.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Docs include a deployment decision matrix comparing Docker/Compose, Render, Fly.io, Vercel/static UI, Railway, Cloud Run, and Helm/Kubernetes
- [ ] #2 Docker Compose or VPS baseline documents Fleet API, WAF, PostgreSQL, Redis, optional ClickHouse, ports, secrets, and private admin/metrics defaults
- [ ] #3 Docs clearly separate demo/dev settings from production-shaped self-hosting guidance
<!-- AC:END -->
