{{- define "synapse-fleet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "synapse-fleet.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "synapse-fleet.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "synapse-fleet.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "synapse-fleet.image" -}}
{{- $repository := .Values.image.repository -}}
{{- if .Values.global.imageRegistry -}}
{{- $repository = printf "%s/%s" .Values.global.imageRegistry $repository -}}
{{- end -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}

{{- define "synapse-fleet.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "synapse-fleet.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "synapse-fleet.managedSecretName" -}}
{{- printf "%s-secrets" (include "synapse-fleet.fullname" .) -}}
{{- end -}}

{{- define "synapse-fleet.migrationsSecretName" -}}
{{- printf "%s-migrations" (include "synapse-fleet.fullname" .) -}}
{{- end -}}

{{- define "synapse-fleet.uiSecretName" -}}
{{- printf "%s-ui" (include "synapse-fleet.fullname" .) -}}
{{- end -}}

{{- define "synapse-fleet.labels" -}}
{{ include "synapse-fleet.selectorLabels" . }}
helm.sh/chart: {{ include "synapse-fleet.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "synapse-fleet.baseLabels" -}}
helm.sh/chart: {{ include "synapse-fleet.chart" . }}
app.kubernetes.io/name: {{ include "synapse-fleet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "synapse-fleet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "synapse-fleet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end -}}

{{- define "synapse-fleet.apiEnv" -}}
{{- if and .Values.enabled (not (or .Values.database.url .Values.database.existingSecret .Values.secrets.existingSecret)) }}
{{- fail "synapse-fleet requires database.url, database.existingSecret, or secrets.existingSecret" }}
{{- end }}
- name: PORT
  value: {{ .Values.containerPort | quote }}
- name: NODE_ENV
  value: {{ default "production" .Values.env.NODE_ENV | quote }}
- name: HOST
  value: {{ default "0.0.0.0" .Values.env.HOST | quote }}
- name: LOG_LEVEL
  value: {{ default "info" .Values.env.LOG_LEVEL | quote }}
- name: ENABLE_JOB_QUEUE
  value: {{ default "false" .Values.env.ENABLE_JOB_QUEUE | quote }}
{{- with .Values.env.RISK_SERVER_URL }}
- name: RISK_SERVER_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.env.SYNAPSE_DIRECT_URL }}
- name: SYNAPSE_DIRECT_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.cors.origins }}
{{- if gt (len .) 0 }}
- name: CORS_ORIGINS
  value: {{ join "," . | quote }}
{{- end }}
{{- end }}
- name: WS_SENSOR_PATH
  value: {{ default "/ws/sensors" .Values.websocket.sensorPath | quote }}
- name: WS_DASHBOARD_PATH
  value: {{ default "/ws/dashboard" .Values.websocket.dashboardPath | quote }}
- name: WS_HEARTBEAT_INTERVAL_MS
  value: {{ .Values.websocket.heartbeatIntervalMs | quote }}
- name: WS_MAX_SENSOR_CONNECTIONS
  value: {{ .Values.websocket.maxSensorConnections | quote }}
- name: WS_MAX_DASHBOARD_CONNECTIONS
  value: {{ .Values.websocket.maxDashboardConnections | quote }}
{{- if .Values.database.existingSecret }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret | quote }}
      key: {{ default "DATABASE_URL" .Values.database.existingSecretKey | quote }}
{{- else if .Values.secrets.existingSecret }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.databaseUrl | quote }}
{{- else if .Values.database.url }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "synapse-fleet.managedSecretName" . | quote }}
      key: {{ .Values.secrets.keys.databaseUrl | quote }}
{{- end }}
{{- if or .Values.redis.enabled .Values.redis.url .Values.redis.existingSecret }}
{{- if .Values.redis.existingSecret }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret | quote }}
      key: {{ default .Values.secrets.keys.redisUrl .Values.redis.existingSecretKey | quote }}
{{- else if .Values.redis.url }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "synapse-fleet.managedSecretName" . | quote }}
      key: {{ .Values.secrets.keys.redisUrl | quote }}
{{- else if .Values.secrets.existingSecret }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.redisUrl | quote }}
{{- else }}
{{- fail "synapse-fleet redis.enabled requires redis.url, redis.existingSecret, or secrets.existingSecret" }}
{{- end }}
{{- end }}
{{- if .Values.clickhouse.enabled }}
- name: CLICKHOUSE_ENABLED
  value: {{ ternary "true" "false" .Values.clickhouse.enabled | quote }}
{{- if not .Values.clickhouse.host }}
{{- fail "synapse-fleet clickhouse.enabled requires clickhouse.host to be set" }}
{{- end }}
{{- if not .Values.clickhouse.database }}
{{- fail "synapse-fleet clickhouse.enabled requires clickhouse.database to be set" }}
{{- end }}
{{- if not .Values.clickhouse.user }}
{{- fail "synapse-fleet clickhouse.enabled requires clickhouse.user to be set" }}
{{- end }}
- name: CLICKHOUSE_HOST
  value: {{ .Values.clickhouse.host | quote }}
- name: CLICKHOUSE_HTTP_PORT
  value: {{ .Values.clickhouse.httpPort | quote }}
- name: CLICKHOUSE_DB
  value: {{ .Values.clickhouse.database | quote }}
- name: CLICKHOUSE_USER
  value: {{ .Values.clickhouse.user | quote }}
- name: CLICKHOUSE_COMPRESSION
  value: {{ ternary "true" "false" .Values.clickhouse.compression | quote }}
- name: CLICKHOUSE_MAX_CONNECTIONS
  value: {{ .Values.clickhouse.maxConnections | quote }}
{{- if .Values.clickhouse.existingSecret }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.clickhouse.existingSecret | quote }}
      key: {{ default .Values.secrets.keys.clickhousePassword .Values.clickhouse.existingSecretKey | quote }}
{{- else if .Values.clickhouse.password }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "synapse-fleet.managedSecretName" . | quote }}
      key: {{ .Values.secrets.keys.clickhousePassword | quote }}
{{- else if .Values.secrets.existingSecret }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.clickhousePassword | quote }}
{{- else }}
{{- fail "synapse-fleet clickhouse.enabled requires clickhouse.password, clickhouse.existingSecret, or secrets.existingSecret" }}
{{- end }}
{{- end }}
{{- if or .Values.secrets.existingSecret .Values.secrets.create }}
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ default (include "synapse-fleet.managedSecretName" .) .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.jwtSecret | quote }}
- name: TELEMETRY_JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ default (include "synapse-fleet.managedSecretName" .) .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.telemetryJwtSecret | quote }}
- name: CONFIG_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ default (include "synapse-fleet.managedSecretName" .) .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.configEncryptionKey | quote }}
{{- end }}
{{- if .Values.metrics.enabled }}
{{- if .Values.metrics.serviceMonitor.bearerTokenSecret }}
- name: METRICS_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.metrics.serviceMonitor.bearerTokenSecret | quote }}
      key: {{ default .Values.secrets.keys.metricsAuthToken .Values.metrics.serviceMonitor.bearerTokenKey | quote }}
{{- else if .Values.secrets.existingSecret }}
- name: METRICS_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret | quote }}
      key: {{ .Values.secrets.keys.metricsAuthToken | quote }}
{{- else if .Values.secrets.create }}
- name: METRICS_AUTH_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "synapse-fleet.managedSecretName" . | quote }}
      key: {{ .Values.secrets.keys.metricsAuthToken | quote }}
{{- else }}
{{- fail "synapse-fleet metrics.enabled requires metrics.serviceMonitor.bearerTokenSecret, secrets.existingSecret, or secrets.create=true" }}
{{- end }}
{{- end }}
{{- end -}}
