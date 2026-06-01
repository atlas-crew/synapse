---
id: TASK-103.11
title: Document Railway and Cloud Run managed-container deployment notes
status: To Do
assignee: []
created_date: '2026-06-01 19:07'
labels:
  - documentation
  - deployment
  - railway
  - cloud-run
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.7
references:
  - apps/signal-horizon/Dockerfile
  - docs/dockerhub-synapse-fleet.md
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add pragmatic managed-container notes for Railway and Google Cloud Run. These do not need to become the primary recommendation, but they should tell users what is viable, what is demo/staging-only, and where Fleet API WebSockets or WAF proxy behavior need extra care.

Keep the guidance honest: if a provider is a poor fit for WAF proxy traffic, say that and point to Fly, VPS, or Kubernetes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Railway notes cover Fleet API deployment, DATABASE_URL, Redis, secrets, migrations, health checks, and dashboard URL configuration
- [ ] #2 Cloud Run notes cover container deployment, WebSocket reconnect expectations, request timeout/session behavior, scaling limits, secrets, and external Postgres/Redis choices
- [ ] #3 Guide states whether WAF deployment is supported, discouraged, or better handled by Fly/VPS/Kubernetes for each provider
<!-- AC:END -->
