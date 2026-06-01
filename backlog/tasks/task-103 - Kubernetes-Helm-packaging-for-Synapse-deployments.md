---
id: TASK-103
title: Kubernetes + Helm packaging for Synapse deployments
status: To Do
assignee: []
created_date: '2026-06-01 18:53'
updated_date: '2026-06-01 18:55'
labels:
  - feature
  - helm
  - kubernetes
  - deployment
milestone: Kubernetes + Helm Packaging
dependencies: []
references:
  - README.md
  - docs/dockerhub-synapse-fleet.md
  - docs/dockerhub-synapse-waf.md
documentation:
  - >-
    backlog/docs/deployment/kubernetes-helm-packaging-plan/doc-1 -
    Kubernetes-and-Helm-packaging-plan.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Track the work needed to make Synapse deployable through supported Helm charts. The scope includes a Fleet control-plane chart, WAF sensor chart, umbrella chart, chart validation/release automation, and operator-facing documentation.

Use `backlog/docs/deployment/kubernetes-helm-packaging-plan/doc-1 - Kubernetes-and-Helm-packaging-plan.md` as the current planning source. Keep production installs oriented around externally managed PostgreSQL/Redis while allowing demo/dev profiles to bundle dependencies.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A milestone exists for Kubernetes and Helm packaging work
- [ ] #2 Child tasks cover Fleet chart, WAF chart, umbrella/demo chart, CI release packaging, and operator documentation
- [ ] #3 The backlog doc captures chart strategy, production defaults, values surface, and safety defaults
- [ ] #4 Parent remains open until the component chart, umbrella chart, CI/release, and docs tasks are Done
<!-- AC:END -->
