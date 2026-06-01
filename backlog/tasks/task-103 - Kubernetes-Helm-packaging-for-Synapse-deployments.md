---
id: TASK-103
title: Synapse deployment packaging and hosting options
status: To Do
assignee: []
created_date: '2026-06-01 18:53'
updated_date: '2026-06-01 19:06'
labels:
  - feature
  - helm
  - kubernetes
  - deployment
  - render
  - fly
  - vercel
  - railway
  - cloud-run
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
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Track the work needed to make Synapse deployable across the main hosting paths operators are likely to choose: Docker/Compose, Render, Fly.io, Vercel/static dashboard hosting, Railway, Cloud Run, and Kubernetes through Helm.

Use `backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 - Synapse-deployment-packaging-plan.md` as the current planning source. Keep production installs oriented around externally managed PostgreSQL/Redis where appropriate, keep admin/metrics private by default, and make demo/dev profiles clearly non-production.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A milestone exists for Synapse deployment packaging work across hosted, container, static UI, and Kubernetes paths
- [ ] #2 Child tasks cover Docker/Compose baseline, Render, Fly.io, Vercel/static dashboard hosting, Railway/Cloud Run notes, Fleet chart, WAF chart, umbrella/demo chart, CI release packaging, and operator documentation
- [ ] #3 The backlog doc captures deployment tracks, decision guidance, Helm strategy, production defaults, values surface, and safety defaults
- [ ] #4 Parent remains open until all provider documentation, component chart, umbrella chart, CI/release, and docs tasks are Done
<!-- AC:END -->
