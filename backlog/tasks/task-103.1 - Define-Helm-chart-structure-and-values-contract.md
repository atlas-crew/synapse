---
id: TASK-103.1
title: Define Helm chart structure and values contract
status: Done
assignee:
  - '@myself'
created_date: '2026-06-01 18:54'
updated_date: '2026-06-02 00:35'
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
    backlog/docs/deployment/synapse-deployment-packaging-plan/doc-1 -
    Synapse-deployment-packaging-plan.md
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
- [x] #1 Chart boundaries are documented for synapse-fleet, synapse-waf, and the umbrella synapse chart
- [x] #2 values.yaml contract covers images, env/secrets, ingress, services, WAF config, resources, security context, metrics, and dependency toggles
- [x] #3 Production defaults prefer externally managed PostgreSQL and Redis, with demo/dev dependency profiles documented separately
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Review the existing deployment plan, Docker/Render packaging, platform map, and relevant Fleet/WAF config surfaces.
2. Add a developer-facing Helm chart contract under docs/development/plans and update docs/NAVIGATOR.md.
3. Define chart boundaries for synapse-fleet, synapse-waf, and umbrella synapse, including migration, ingress/WebSocket, UI URL, and dependency behavior.
4. Specify the values.yaml contract for images, env/secrets, ingress, services, WAF config, resources, security context, metrics, and dependency toggles.
5. Validate the docs, run independent review and test-audit gates, mark AC complete, and commit with cortex git commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented docs/development/plans/synapse-helm-chart-contract.md and linked it from docs/NAVIGATOR.md. The contract defines synapse-fleet, synapse-waf, and umbrella synapse chart boundaries; values keys; production and demo/dev profiles; env and secret precedence; WAF config generation; migration Job behavior; ingress/WebSocket assumptions; UI URL wiring; resource ownership rules; and TASK-103.2 validation/render-test requirements.

Validation: git diff --check passed for the changed docs/backlog files. AI-tell scan on the new contract doc passed with no matches. Independent review artifacts were iterated until only the expected backlog status closeout remained; latest review: .agents/reviews/review-20260601-203148.md. Test audit artifact .agents/reviews/test-audit-20260601-203335.md reported missing Helm render tests, which is expected before chart scaffolding and is captured in the TASK-103.2 test requirements section.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the Synapse Helm chart design contract and navigator entry. The contract gives the scaffold task a concrete chart/value surface, secure default posture, migration and ingress assumptions, WAF secret handling constraints, and render-test checklist for TASK-103.2.
<!-- SECTION:FINAL_SUMMARY:END -->
