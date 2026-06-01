---
id: TASK-103.9
title: Add Fly.io deployment guide for Fleet and WAF containers
status: To Do
assignee: []
created_date: '2026-06-01 19:06'
labels:
  - documentation
  - deployment
  - fly
  - synapse-pingora
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.7
references:
  - apps/signal-horizon/Dockerfile
  - apps/synapse-pingora/Dockerfile
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
Add a container-native Fly.io deployment path for users who want managed regions and Docker image deployment without Kubernetes. Fleet and WAF can be documented separately so operators can run the control plane, sensors, or both.

Call out what should be private, what can be public, and how Fleet/WAF telemetry endpoints are wired across apps or networks.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fly.io guide covers Fleet API deployment with secrets, managed/external Postgres, Redis, health checks, WebSocket behavior, and migrations
- [ ] #2 Guide covers WAF container deployment with proxy/admin services, config mounting or secret injection, telemetry endpoint, and private admin defaults
- [ ] #3 Guide includes sample fly.toml snippets or values for Fleet-only, WAF-only, and Fleet+WAF topologies
<!-- AC:END -->
