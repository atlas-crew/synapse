---
id: TASK-103.10
title: Document Vercel and static dashboard hosting
status: To Do
assignee: []
created_date: '2026-06-01 19:07'
labels:
  - documentation
  - deployment
  - vercel
  - signal-horizon-ui
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.7
references:
  - apps/signal-horizon/ui/package.json
  - render.yaml
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create the static dashboard hosting guide for Vercel and similar static hosts. This should prevent users from trying to run Fleet API or WAF as serverless functions while still making the dashboard easy to host independently.

Include concrete environment variables and verification steps for REST and dashboard WebSocket connectivity.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Guide explains that Vercel/static hosts are dashboard-only and require Fleet API/WebSockets to be hosted elsewhere
- [ ] #2 Guide documents VITE_API_URL, VITE_WS_URL, API key handling, CORS origins, and common mixed-content/TLS pitfalls
- [ ] #3 Guide includes hybrid examples such as Vercel UI plus Render/Fly/Cloud Run/Kubernetes Fleet API
<!-- AC:END -->
