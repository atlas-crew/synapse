---
id: TASK-103.8
title: Harden Render deployment guide and Blueprint path
status: To Do
assignee: []
created_date: '2026-06-01 19:06'
labels:
  - documentation
  - deployment
  - render
  - signal-horizon-api
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.7
references:
  - render.yaml
  - apps/signal-horizon/api/package.json
  - apps/signal-horizon/ui/package.json
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Make Render a supported managed-hosting path rather than an incidental `render.yaml`. The guide should explain the existing Blueprint, identify required manual environment values, and document how operators verify Fleet API/UI behavior after deploy.

Keep WAF deployment as a separate container/self-hosted or Fly/Kubernetes concern unless a Render-specific WAF path is validated.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Render guide maps the existing Blueprint services to Fleet UI, Fleet API, Postgres, Redis/Key Value, env vars, health checks, and predeploy migrations
- [ ] #2 Guide documents required secret values, CORS/WebSocket URLs, and production ClickHouse posture
- [ ] #3 Guide includes verification steps for health, REST, WebSocket dashboard, and sensor telemetry connectivity
<!-- AC:END -->
