# Authentication & Authorization Patterns

This document describes the canonical patterns for protecting routes in the Signal Horizon API.

## Canonical Pattern: `authorize()`

The `authorize()` middleware is the recommended way to protect routes. It combines authentication checks, scope validation, role requirements, and tenant isolation into a single, readable call.

### Basic Usage

Protect a route with a required scope:

```typescript
router.get('/data', 
  authorize(prisma, { scopes: 'data:read' }), 
  handler
);
```

### Role Requirements

Require a minimum role level (viewer < operator < admin):

```typescript
router.post('/settings', 
  authorize(prisma, { scopes: 'settings:write', role: 'operator' }), 
  handler
);
```

### Tenant Isolation

Automatically verify that a resource belongs to the authenticated tenant:

```typescript
router.get('/sensors/:sensorId',
  authorize(prisma, {
    scopes: 'sensor:read',
    tenant: { resource: 'sensor', param: 'sensorId' }
  }),
  handler
);
```

Supported resource types for tenant isolation:
- `sensor`
- `policy`
- `template`
- `command`

## Legacy Patterns (Deprecated)

Previously, routes used multiple middlewares which was more verbose and error-prone:

```typescript
// Pattern B (Deprecated)
router.delete('/:id',
  requireScope('resource:write'),
  requireRole('operator'),
  requireTenant(prisma, 'resource', 'id'),
  handler
);
```

## Internal Roles

Roles are derived from scopes:

| Role | Description | Scopes (Examples) |
|------|-------------|-------------------|
| `viewer` | Read-only access | `*:read` |
| `operator` | Operational access | `*:write`, `command:execute` |
| `admin` | Full administrative access | `fleet:admin`, `*:admin` |

## RBAC Roles (Phase 3+)

With the introduction of User RBAC, the following roles are defined in the database:

- `VIEWER`: Read-only access to tenant data.
- `OPERATOR`: Can perform operational tasks and configuration.
- `ADMIN`: Full access to tenant management.
- `SUPER_ADMIN`: Global administrative access across all tenants.
