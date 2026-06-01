---
id: TASK-103.4
title: Implement synapse-waf Helm chart
status: To Do
assignee: []
created_date: '2026-06-01 18:54'
updated_date: '2026-06-01 19:06'
labels:
  - feature
  - helm
  - kubernetes
  - synapse-pingora
milestone: Kubernetes + Helm Packaging
dependencies:
  - TASK-103.2
references:
  - apps/synapse-pingora/Dockerfile
  - docs/dockerhub-synapse-waf.md
  - apps/synapse-pingora/config.yaml
documentation:
  - >-
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
parent_task_id: TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build the WAF sensor chart for Kubernetes operators. The chart should keep the reverse-proxy/admin split explicit: proxy traffic may be exposed intentionally, while admin and metrics stay internal unless the operator opts in.

The chart should support ConfigMap or Secret-backed configuration, telemetry to Fleet, and future observability integrations such as Prometheus ServiceMonitor.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Chart deploys Synapse WAF with configurable image, config.yaml source, resources, probes, service account, and pod security settings
- [ ] #2 Proxy, admin, health, and metrics services are configurable with admin/metrics ClusterIP by default
- [ ] #3 Chart supports telemetry wiring to Synapse Fleet through endpoint and secret-backed API key values
- [ ] #4 Chart supports Deployment by default and documents when DaemonSet mode is appropriate
<!-- AC:END -->
