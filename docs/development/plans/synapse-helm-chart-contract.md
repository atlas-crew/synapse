# Synapse Helm Chart Contract

Status: design contract for TASK-103.1

Audience: agents and maintainers implementing `TASK-103.2` through
`TASK-103.6`. This document defines the chart boundaries and values keys before
any chart scaffolding lands.

## Source Constraints

The chart design is grounded in the current deployable shape:

- `render.yaml` splits Fleet UI, Fleet API, PostgreSQL, and Redis/Key Value.
- `apps/signal-horizon/Dockerfile` builds the `nickcrew/synapse-fleet` runtime
  image. It exposes port `3100` and includes `curl` for health checks.
- `apps/synapse-pingora/Dockerfile` builds the `nickcrew/synapse-waf` runtime
  image. It reads `/app/config.yaml` by default and exposes ports `6190` and
  `6191`.
- `docs/architecture/platform-map.md` treats the Fleet API as a long-running
  REST and WebSocket service, the Fleet UI as a static dashboard, and the WAF as
  a reverse proxy plus private admin surface.
- `site/deployment/docker.md` is the current Docker baseline. It keeps WAF admin
  private, requires Fleet secrets, disables ClickHouse by default, and treats
  Redis as required before scaling Fleet API beyond one instance.

## Chart Set

Ship three charts under `charts/`.

| Chart | Type | Owns | Does not own |
| --- | --- | --- | --- |
| `synapse-fleet` | application | Fleet API Deployment, Service, optional Ingress, optional UI/static config, migration Job, Secret/ConfigMap templates, metrics hooks | WAF proxy workloads, production databases by default |
| `synapse-waf` | application | WAF Deployment by default, optional DaemonSet mode, WAF ConfigMap/Secret, proxy Service, private admin Service, telemetry Secret refs | Fleet API, PostgreSQL, Redis, ClickHouse |
| `synapse` | umbrella | Dependency wiring between `synapse-fleet` and `synapse-waf`, demo/dev dependency toggles, shared global values | New Kubernetes resources outside child charts unless they only wire child values |

### `synapse-fleet`

Primary resources:

- `Deployment` for the Fleet API container.
- `Service` named for the Fleet API, targeting port `3100`.
- optional `Ingress` for HTTPS/WSS traffic to the API.
- optional `ConfigMap` for non-secret environment values.
- optional `Secret` only when the operator chooses chart-managed secrets.
- `Job` for Prisma migrations.
- optional `ServiceMonitor` or scrape annotations.
- optional UI static hosting mode if the chart later serves built UI assets from
  the Fleet image or a companion static container.

Default posture:

- one replica
- `CLICKHOUSE_ENABLED=false`
- no bundled PostgreSQL or Redis
- no public admin-only endpoints
- migration Job disabled until `fleet.migrations.enabled=true`

### `synapse-waf`

Primary resources:

- `Deployment` by default.
- `DaemonSet` only when `waf.workload.kind=DaemonSet`.
- `ConfigMap` or `Secret` for generated `config.yaml`, unless
  `waf.config.existingConfigMap` or `waf.config.existingSecret` is set.
- proxy `Service` for port `6190`.
- admin `Service` for port `6191`, `ClusterIP` by default.
- optional proxy `Ingress` or `LoadBalancer` Service.
- optional metrics scrape annotations or `ServiceMonitor`.

Default posture:

- expose proxy only as a `ClusterIP` Service until explicitly changed
- keep admin/metrics private
- mount WAF config at `/app/config.yaml`
- wire telemetry to Fleet only when `waf.telemetry.enabled=true`

### `synapse`

The umbrella chart composes child charts. It should not duplicate child
templates.

Responsibilities:

- declare `synapse-fleet` and `synapse-waf` dependencies in `Chart.yaml` with
  aliases `fleet` and `waf`, so root values stay aligned with this contract
- provide a demo profile that can enable bundled PostgreSQL, Redis, and
  ClickHouse
- pass the Fleet service DNS name into WAF telemetry values
- pass the generated or referenced Fleet telemetry secret into WAF telemetry
  values for demo/dev installs
- expose a single production-shaped example with external database and Redis
  references

## Values Contract

The keys below are the contract for the first chart scaffolding pass. Later
tasks may add keys, but they should not rename these without updating this
document and any examples.

```yaml
global:
  imageRegistry: ""
  imagePullSecrets: []
  nameOverride: ""
  fullnameOverride: ""
  commonLabels: {}
  commonAnnotations: {}
  storageClass: ""

fleet:
  enabled: true
  replicaCount: 1
  containerPort: 3100

  image:
    repository: nickcrew/synapse-fleet
    tag: latest
    pullPolicy: IfNotPresent

  serviceAccount:
    create: true
    name: ""
    annotations: {}

  podSecurityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault

  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL

  writableTmp:
    enabled: true
    mountPath: /tmp
    sizeLimit: ""

  service:
    type: ClusterIP
    port: 3100
    annotations: {}

  ingress:
    enabled: false
    className: ""
    annotations: {}
    hosts: []
    tls: []
    websocket:
      enabled: true
      controller: ""
      proxyReadTimeoutSeconds: 300
      proxySendTimeoutSeconds: 300

  env:
    NODE_ENV: production
    HOST: 0.0.0.0
    LOG_LEVEL: info
    ENABLE_JOB_QUEUE: "false"

  secrets:
    create: false
    existingSecret: ""
    keys:
      databaseUrl: DATABASE_URL
      redisUrl: REDIS_URL
      jwtSecret: JWT_SECRET
      telemetryJwtSecret: TELEMETRY_JWT_SECRET
      configEncryptionKey: CONFIG_ENCRYPTION_KEY
      metricsAuthToken: METRICS_AUTH_TOKEN
      clickhousePassword: CLICKHOUSE_PASSWORD

  database:
    external: true
    url: ""
    existingSecret: ""
    existingSecretKey: DATABASE_URL

  redis:
    enabled: false
    external: true
    url: ""
    existingSecret: ""
    existingSecretKey: REDIS_URL

  clickhouse:
    enabled: false
    external: true
    host: ""
    httpPort: 8123
    database: signal_horizon
    user: default
    password: ""
    existingSecret: ""
    existingSecretKey: CLICKHOUSE_PASSWORD
    compression: true
    maxConnections: 25

  cors:
    origins: []

  websocket:
    sensorPath: /ws/sensors
    dashboardPath: /ws/dashboard
    heartbeatIntervalMs: 30000
    maxSensorConnections: 1000
    maxDashboardConnections: 100

  ui:
    enabled: false
    publicApiUrl: ""
    publicWebSocketUrl: ""
    apiKey:
      value: ""
      existingSecret: ""
      existingSecretKey: VITE_HORIZON_API_KEY

  migrations:
    enabled: false
    command:
      - npx
      - prisma
      - migrate
      - deploy
    backoffLimit: 1
    ttlSecondsAfterFinished: 300
    hook:
      enabled: false
      deletePolicy: before-hook-creation,hook-succeeded

  probes:
    liveness:
      enabled: true
      path: /health/live
    readiness:
      enabled: true
      path: /ready
    startup:
      enabled: false
      path: /health

  resources: {}
  nodeSelector: {}
  tolerations: []
  affinity: {}
  autoscaling:
    enabled: false
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
  podDisruptionBudget:
    enabled: false
    minAvailable: 1
  networkPolicy:
    enabled: false
  metrics:
    enabled: false
    path: /metrics
    serviceMonitor:
      enabled: false
      bearerTokenSecret: ""
      bearerTokenKey: METRICS_AUTH_TOKEN

waf:
  enabled: true
  replicaCount: 1

  workload:
    kind: Deployment

  image:
    repository: nickcrew/synapse-waf
    tag: latest
    pullPolicy: IfNotPresent

  serviceAccount:
    create: true
    name: ""
    annotations: {}

  podSecurityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault

  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL

  writableTmp:
    enabled: true
    mountPath: /tmp
    sizeLimit: ""

  config:
    mountPath: /app/config.yaml
    existingConfigMap: ""
    existingSecret: ""
    raw: ""
    server:
      listen: 0.0.0.0:6190
      adminListen: 0.0.0.0:6191
      workers: 0
    upstreams: []
    sites: []

  telemetry:
    enabled: false
    endpoint: ""
    apiKey:
      value: ""
      existingSecret: ""
      existingSecretKey: apiKey
    instanceId: ""

  horizon:
    enabled: false
    hubUrl: ""
    sensorId: ""
    sensorName: ""
    apiKey:
      value: ""
      existingSecret: ""
      existingSecretKey: apiKey

  service:
    proxy:
      type: ClusterIP
      port: 6190
      annotations: {}
    admin:
      type: ClusterIP
      port: 6191
      annotations: {}

  ingress:
    proxy:
      enabled: false
      className: ""
      annotations: {}
      hosts: []
      tls: []
    admin:
      enabled: false
      className: ""
      annotations: {}
      hosts: []
      tls: []

  probes:
    readiness:
      enabled: true
      path: /status
      port: admin
    liveness:
      enabled: true
      path: /status
      port: admin

  resources: {}
  nodeSelector: {}
  tolerations: []
  affinity: {}
  autoscaling:
    enabled: false
  podDisruptionBudget:
    enabled: false
  networkPolicy:
    enabled: false
  metrics:
    enabled: false
    path: /metrics
    serviceMonitor:
      enabled: false
      bearerTokenSecret: ""
      bearerTokenKey: METRICS_AUTH_TOKEN

postgresql:
  enabled: false
redis:
  enabled: false
clickhouse:
  enabled: false
```

The `waf.horizon` key mirrors the current WAF `config.yaml` structure. Keep it
until the WAF config accepts a renamed Fleet key.

All `ingress.*.hosts` and `ingress.*.tls` arrays use the standard Helm object
shape. Host entries should support `host`, `paths`, and `pathType`; TLS entries
should support `secretName` and `hosts`.

## Required Defaults

Production defaults:

- `fleet.database.external=true`
- `fleet.redis.external=true`
- `fleet.clickhouse.enabled=false`
- `fleet.secrets.create=false`
- `waf.service.admin.type=ClusterIP`
- `waf.ingress.admin.enabled=false`
- no default secret values
- no default public WAF proxy ingress
- no automatic migration hook unless explicitly enabled

Demo/dev profile:

- may enable bundled PostgreSQL, Redis, and ClickHouse through root dependency
  keys such as `postgresql.enabled`, `redis.enabled`, and `clickhouse.enabled`
- may enable chart-managed secrets with generated or documented placeholder
  values
- may wire WAF telemetry to the in-cluster Fleet service
- must enable Fleet migrations when bundled PostgreSQL is enabled
- must share the generated or referenced telemetry secret with WAF telemetry
- must clearly label itself as non-production

## Values Profiles

Production-shaped external services:

```yaml
fleet:
  database:
    external: true
    existingSecret: synapse-fleet-database
    existingSecretKey: DATABASE_URL
  redis:
    external: true
    existingSecret: synapse-fleet-redis
    existingSecretKey: REDIS_URL
  clickhouse:
    enabled: false
  secrets:
    create: false
    existingSecret: synapse-fleet-secrets

waf:
  service:
    proxy:
      type: ClusterIP
    admin:
      type: ClusterIP
  ingress:
    proxy:
      enabled: false
    admin:
      enabled: false

postgresql:
  enabled: false
redis:
  enabled: false
clickhouse:
  enabled: false
```

Demo/dev bundled services:

```yaml
fleet:
  database:
    external: false
  redis:
    enabled: true
    external: false
  clickhouse:
    enabled: false
  secrets:
    create: true
  migrations:
    enabled: true

waf:
  telemetry:
    enabled: true
    endpoint: http://synapse-fleet:3100/telemetry
    apiKey:
      existingSecret: synapse-fleet-secrets
      existingSecretKey: TELEMETRY_JWT_SECRET
  service:
    proxy:
      type: ClusterIP
    admin:
      type: ClusterIP

postgresql:
  enabled: true
redis:
  enabled: true
clickhouse:
  enabled: false
```

## Environment Mapping

Fleet environment values should map from structured values rather than asking
operators to hand-write arbitrary env arrays for the common path.

`fleet.env` is for extra non-secret environment values only. Templates must not
let `fleet.env` override variables owned by structured sections such as
`fleet.database`, `fleet.redis`, `fleet.clickhouse`, `fleet.websocket`,
`fleet.cors`, or `fleet.secrets`.

| Env var | Source value | Secret by default |
| --- | --- | --- |
| `PORT` | `fleet.containerPort` stringified | no |
| `DATABASE_URL` | `fleet.database.url` or secret ref | yes |
| `REDIS_URL` | `fleet.redis.url` or secret ref | yes |
| `JWT_SECRET` | `fleet.secrets` | yes |
| `TELEMETRY_JWT_SECRET` | `fleet.secrets` | yes |
| `CONFIG_ENCRYPTION_KEY` | `fleet.secrets` | yes |
| `METRICS_AUTH_TOKEN` | `fleet.secrets` | yes |
| `CLICKHOUSE_PASSWORD` | `fleet.clickhouse.password` or secret ref | yes |
| `CLICKHOUSE_ENABLED` | `fleet.clickhouse.enabled` | no |
| `CLICKHOUSE_HOST` | `fleet.clickhouse.host` | no |
| `CLICKHOUSE_HTTP_PORT` | `fleet.clickhouse.httpPort` | no |
| `CLICKHOUSE_DB` | `fleet.clickhouse.database` | no |
| `CLICKHOUSE_USER` | `fleet.clickhouse.user` | no |
| `CORS_ORIGINS` | `fleet.cors.origins` joined with commas | no |
| `WS_SENSOR_PATH` | `fleet.websocket.sensorPath` | no |
| `WS_DASHBOARD_PATH` | `fleet.websocket.dashboardPath` | no |
| `WS_HEARTBEAT_INTERVAL_MS` | `fleet.websocket.heartbeatIntervalMs` | no |
| `WS_MAX_SENSOR_CONNECTIONS` | `fleet.websocket.maxSensorConnections` | no |
| `WS_MAX_DASHBOARD_CONNECTIONS` | `fleet.websocket.maxDashboardConnections` | no |

The UI still accepts `VITE_HORIZON_API_KEY` during the Synapse Fleet rename
window. Preserve that key name until the application accepts a replacement.

Secret precedence:

1. service-specific existing secret, such as `fleet.database.existingSecret`
2. shared Fleet existing secret from `fleet.secrets.existingSecret`
3. chart-managed secret when `fleet.secrets.create=true`
4. literal values from `fleet.database.url`, `fleet.redis.url`, or matching
   structured fields

If two sources are set for the same secret-backed env var, templates should
prefer the highest-precedence source and emit only one environment entry.

Connection-string sections such as `fleet.database`, `fleet.redis`, and
`fleet.clickhouse` use section-level `existingSecret` fields because each
section resolves to one environment variable. API-key fields use nested
`value`, `existingSecret`, and `existingSecretKey` keys.

## WAF Config Mapping

The WAF chart writes a YAML config file for the container. Secret-backed API
keys must not be interpolated into a ConfigMap during Helm templating.

| Values key | Config output | Secret by default |
| --- | --- | --- |
| `waf.config.raw` | entire `/app/config.yaml` when set | no |
| `waf.config.server.listen` | `server.listen` | no |
| `waf.config.server.adminListen` | `server.admin_listen` | no |
| `waf.config.server.workers` | `server.workers` | no |
| `waf.config.upstreams` | `upstreams` | no |
| `waf.config.sites` | `sites` | no |
| `waf.telemetry.enabled` | `telemetry.enabled` | no |
| `waf.telemetry.endpoint` | `telemetry.endpoint` | no |
| `waf.telemetry.apiKey.value` or secret ref | `telemetry.api_key` | yes |
| `waf.telemetry.instanceId` | `telemetry.instance_id` | no |
| `waf.horizon.enabled` | `horizon.enabled` | no |
| `waf.horizon.hubUrl` | `horizon.hub_url` | no |
| `waf.horizon.sensorId` | `horizon.sensor_id` | no |
| `waf.horizon.sensorName` | `horizon.sensor_name` | no |
| `waf.horizon.apiKey.value` or secret ref | `horizon.api_key` | yes |

If `waf.config.existingConfigMap` or `waf.config.existingSecret` is set, the
chart should mount that file and skip generated config. If `waf.config.raw` is
set, it wins over the structured WAF config sections and should be documented
as operator-owned YAML.

When `waf.telemetry.apiKey.value` or `waf.horizon.apiKey.value` is set, the
generated WAF config must be stored in a Kubernetes `Secret`, not a `ConfigMap`.
When either API key uses `existingSecret`, the chart must mount the key through
`valueFrom.secretKeyRef` and render the final config inside the pod at startup,
or the WAF runtime must support environment overrides for those keys. The chart
must not try to read an existing Secret value during Helm templating.

## Migration Job Behavior

The Fleet chart must support a migration Job because Render already runs
`db:migrate:prod` before deploy. Kubernetes should expose the same behavior.

Contract:

- `fleet.migrations.enabled=false` by default.
- when enabled, the Job uses the Fleet image and the same secret/env sources as
  the Deployment.
- default command is `npx prisma migrate deploy`.
- hook mode is optional through `fleet.migrations.hook.enabled`.
- non-hook mode should create a normal Job that GitOps tools can reconcile.
- non-hook Job names must include a unique release component, such as the Helm
  release revision, or the chart must document the GitOps deletion policy that
  makes repeated migrations safe.
- rollback docs must explain that schema rollback is not automatic.

## Ingress and WebSocket Assumptions

Fleet API ingress must account for long-lived WebSockets:

- route REST and `/ws/dashboard` through the same Fleet API Service unless a
  future chart explicitly splits them
- include timeout annotations through values, not hard-coded controller names
- keep the base chart ingress-controller neutral unless
  `fleet.ingress.websocket.controller` is set to a supported controller such as
  `nginx`
- expose `fleet.ingress.websocket.proxyReadTimeoutSeconds` and
  `proxySendTimeoutSeconds`

WAF proxy ingress is separate from Fleet ingress. WAF admin ingress is disabled
by default and should require an explicit warning in examples if enabled.

## Public UI URL Wiring

The first chart pass does not need to solve all static UI hosting modes. It must
reserve values for them:

- `fleet.ui.publicApiUrl` maps to `VITE_API_URL`
- `fleet.ui.publicWebSocketUrl` maps to `VITE_WS_URL`
- `fleet.ui.apiKey.*` maps to `VITE_HORIZON_API_KEY`

If the Fleet image serves the built UI from the API container, the same public
URL values still drive browser-side configuration. If a later chart adds a
separate static UI workload, it must use the same `fleet.ui` values.

## Resource Ownership Rules

- Child charts own their own labels, selectors, services, secrets, config maps,
  probes, and network policy.
- The umbrella chart passes values into children and should not create duplicate
  Services or Secrets for child workloads.
- Generated `config.yaml` for WAF belongs to `synapse-waf`.
- Database and Redis dependency charts are disabled by default.
- Dependency toggles use root-level subchart keys such as `postgresql.enabled`,
  `redis.enabled`, and `clickhouse.enabled`.
- Any bundled dependency must be replaceable through external URL or existing
  secret values.
- Fleet pods should mount an `emptyDir` at `/tmp` by default through
  `fleet.writableTmp` because the container root filesystem is read-only.
- WAF `config.yaml` file mounts must use `subPath` so the generated config can
  land at `/app/config.yaml` without replacing the container's `/app`
  directory.
- WAF pods should mount an `emptyDir` at `/tmp` by default through
  `waf.writableTmp` because the container root filesystem is read-only.
- WAF container ports must be named `proxy` and `admin` so Services and probes
  can use stable named target ports.
- `fleet.service.port` is the Kubernetes Service port. The Fleet container
  listens on `fleet.containerPort`, which defaults to `3100`; templates must set
  `targetPort` explicitly instead of assuming Service port and container port
  are identical.
- WAF autoscaling must render an HPA only when
  `waf.workload.kind=Deployment`. HPA resources must not target a DaemonSet.

## Validation Requirements for TASK-103.2

The scaffold task should add enough chart structure to validate this contract:

- `helm lint charts/synapse-fleet`
- `helm lint charts/synapse-waf`
- `helm lint charts/synapse`
- `helm template` for default values
- `helm template` for a demo/dev values file
- `helm template` for a production-shaped external database values file

The first scaffold does not need to pass cluster admission. It does need stable
chart names, stable values keys, and templates that render without missing
required values in the default non-production mode.

TASK-103.2 should add chart render tests for these behaviors:

- default `synapse-fleet` Deployment and Service render with container and
  Service wiring for port `3100`
- `fleet.env` cannot override structured values for database, Redis,
  ClickHouse, WebSocket, CORS, or secret-backed variables
- secret-backed Fleet env vars follow the documented precedence order and emit
  only one source per variable
- Fleet migration Jobs render either with Helm hook annotations and delete
  policy or with a non-hook name that is safe for repeated upgrades
- Fleet Ingress renders WebSocket timeout annotations from values when enabled
- UI URL values map to `VITE_API_URL`, `VITE_WS_URL`, and
  `VITE_HORIZON_API_KEY`
- WAF renders a `Deployment` or `DaemonSet` from `waf.workload.kind` while
  preserving the same pod spec and config mounts
- WAF admin defaults stay private: admin Service `ClusterIP`, no admin Ingress
  from default values
- WAF generated config mounts at `/app/config.yaml` unless an existing config
  source overrides it
- umbrella demo/dev rendering wires WAF telemetry to the in-cluster Fleet
  Service and uses the same telemetry secret name/key generated or referenced
  by Fleet
- WAF API keys from existing Secrets are not rendered into ConfigMaps; the chart
  uses a runtime render path or runtime env overrides
- WAF autoscaling is skipped when `waf.workload.kind=DaemonSet`
