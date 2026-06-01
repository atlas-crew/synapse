---
id: TASK-103.7
title: Publish deployment decision matrix and Docker Compose baseline
status: Done
assignee:
  - '@myself'
created_date: '2026-06-01 19:06'
updated_date: '2026-06-01 23:53'
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
- [x] #1 Docs include a deployment decision matrix comparing Docker/Compose, Render, Fly.io, Vercel/static UI, Railway, Cloud Run, and Helm/Kubernetes
- [x] #2 Docker Compose or VPS baseline documents Fleet API, WAF, PostgreSQL, Redis, optional ClickHouse, ports, secrets, and private admin/metrics defaults
- [x] #3 Docs clearly separate demo/dev settings from production-shaped self-hosting guidance
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Review existing public docs, Docker Hub docs, Render config, and site navigation to place the deployment guidance correctly.
2. Add a deployment overview guide with a decision matrix and Docker Compose/VPS baseline.
3. Link the guide from the relevant getting-started or reference index so users can find it.
4. Validate Markdown/frontmatter, run available docs/site checks if present, and request independent review.
5. Mark acceptance criteria complete and commit the documentation slice with cortex git commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented the deployment decision matrix and Docker/VPS baseline as public site documentation. Added `site/deployment/hosting-options.md`, linked it from deployment navigation, refreshed the Docker Compose baseline with current Synapse Fleet image names, private WAF admin defaults, optional ClickHouse profile, fail-closed secret substitutions, and scaling/healthcheck guidance.

Validation: `npm run build` from `site/` passed. Independent review artifact: `.agents/reviews/review-20260601-194712.md` CLEAN. Test audit artifact: `.agents/reviews/test-audit-20260601-194931.md` found no behavioral gaps for the docs-only diff.

Final post-remediation review artifact: `.agents/reviews/review-20260601-195150.md` CLEAN on the exact final diff.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added a public Hosting Options guide for Synapse deployment choices across Docker/Compose, Render, Fly.io, Vercel/static hosting, Railway, Cloud Run, and Helm/Kubernetes. Updated the deployment overview/sidebar to surface the guide, and refreshed the Docker guide so the Compose baseline uses current Synapse Fleet/WAF images, private admin defaults, required fail-closed secrets, optional ClickHouse, and safer scaling/healthcheck guidance.

Validation: `npm run build` in `site/` passed. Review: `.agents/reviews/review-20260601-195150.md` CLEAN. Test audit: `.agents/reviews/test-audit-20260601-194931.md` found no behavioral gaps for docs-only diff.
<!-- SECTION:FINAL_SUMMARY:END -->
