---
id: TASK-23
title: Add JWT testing controls to Auth Coverage Map
status: Done
assignee: []
created_date: '2026-04-05 07:22'
updated_date: '2026-04-05 12:55'
labels:
  - apparatus
  - identity
  - jwt
  - auth-coverage
  - api
  - ui
milestone: m-4
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Integrate Apparatus IdentityApi (JWT debug/forge/verify) into the existing Auth Coverage Map page. When an operator clicks an endpoint on the coverage map, expose a testing panel that lets them:

- **Debug a JWT**: Paste a token → see decoded header/payload, validation result, signing algorithm
- **Forge a token**: Generate a crafted JWT with custom claims, role, expiry for testing access boundaries
- **Verify with bypass checks**: Test for algorithm confusion (none/HS256), expired token acceptance, key confusion

API routes needed:
- `POST /api/v1/apparatus/identity/jwt/debug` → `client.identity.jwtDebug()`
- `POST /api/v1/apparatus/identity/jwt/forge` → `client.identity.jwtForge()`
- `POST /api/v1/apparatus/identity/jwt/verify` → `client.identity.jwtVerify()`
- `GET /api/v1/apparatus/identity/jwks` → `client.identity.jwks()`

UI: Add a collapsible "JWT Testing" panel to the Auth Coverage Map page, or a slide-out drawer when clicking an endpoint.
<!-- SECTION:DESCRIPTION:END -->
