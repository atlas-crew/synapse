# Route Conventions

## File Layout

- One router file per domain: `api/routes/<domain>.ts`.
- Export a factory: `export function create<Domain>Router(deps): Router`.
- Mount in `app-shell.ts` — never in `index.ts` directly.

## Middleware Stack Order

```
requestId
→ security headers
→ rate-limiter
→ content-type check
→ json-depth guard
→ query-limits
→ csrf (for state-changing methods)
→ versioning
→ replay-protection (for idempotent mutations)
→ timeout
→ (route handler)
```

Do not re-order or skip. Put any new middleware in `middleware/` and insert at the right position in `app-shell.ts`.

## Auth

- **Dashboard routes**: API key via `requireApiKey` (checks `X-API-Key` header, validated against Postgres).
- **Sensor routes**: Sensor key (distinct keyspace).
- **Admin routes**: Scope-checked admin token.

## Error Contract

- Throw typed errors from the `errors.ts` module. Middleware converts to HTTP responses.
- Never return `res.status(500).send(...)` from a handler — use the error enum so telemetry captures it.
- 4xx responses include `{ error: { code, message, requestId } }`.

## Versioning

- Prefix routes with `/v1`, `/v2` as appropriate.
- `middleware/versioning.ts` handles deprecation headers.
- Breaking changes get a new version; additive changes don't.

## Testing Route Files

- Use `supertest` against the assembled app, not the router in isolation. Middleware is part of the contract.
- Seed a tenant and pass an API key fixture; don't bypass auth with a test flag in production code.
