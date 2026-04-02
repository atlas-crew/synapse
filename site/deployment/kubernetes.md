---
title: Kubernetes Deployment
---

# Kubernetes Deployment

This guide covers deploying Horizon and Synapse on Kubernetes.

## Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: horizon
```

## Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: horizon-secrets
  namespace: horizon
type: Opaque
stringData:
  DATABASE_URL: postgresql://user:password@postgres:5432/signal_horizon
  JWT_SECRET: your-jwt-secret-min-32-chars
  TELEMETRY_JWT_SECRET: your-telemetry-jwt-secret
  CONFIG_ENCRYPTION_KEY: your-encryption-key
```

## Horizon API

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: horizon-api
  namespace: horizon
spec:
  replicas: 2
  selector:
    matchLabels:
      app: horizon-api
  template:
    metadata:
      labels:
        app: horizon-api
    spec:
      containers:
        - name: horizon-api
          image: nickcrew/horizon:latest
          ports:
            - containerPort: 3100
          envFrom:
            - secretRef:
                name: horizon-secrets
          env:
            - name: NODE_ENV
              value: production
            - name: PORT
              value: "3100"
            - name: CLICKHOUSE_ENABLED
              value: "true"
            - name: CLICKHOUSE_HOST
              value: clickhouse
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 3100
            initialDelaySeconds: 10
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /health/live
              port: 3100
            initialDelaySeconds: 15
            periodSeconds: 10
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
---
apiVersion: v1
kind: Service
metadata:
  name: horizon-api
  namespace: horizon
spec:
  selector:
    app: horizon-api
  ports:
    - port: 3100
      targetPort: 3100
```

## Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: horizon-api
  namespace: horizon
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: horizon-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## Synapse DaemonSet

Deploy Synapse to every node (or a subset using node selectors):

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: synapse
  namespace: horizon
spec:
  selector:
    matchLabels:
      app: synapse
  template:
    metadata:
      labels:
        app: synapse
    spec:
      containers:
        - name: synapse
          image: nickcrew/synapse-waf:latest
          ports:
            - containerPort: 6190
              hostPort: 6190
            - containerPort: 6191
          volumeMounts:
            - name: config
              mountPath: /etc/synapse
          readinessProbe:
            httpGet:
              path: /status
              port: 6191
            initialDelaySeconds: 5
          resources:
            requests:
              cpu: 250m
              memory: 128Mi
            limits:
              cpu: 2000m
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: synapse-config
```

::: tip DaemonSet vs. Deployment
Use a **DaemonSet** when Synapse should run on every edge node. Use a **Deployment** when Synapse instances sit behind an ingress controller and you control replica count independently.
:::

## Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: horizon
  namespace: horizon
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
    nginx.ingress.kubernetes.io/websocket-services: horizon-api
spec:
  tls:
    - hosts:
        - horizon.example.com
      secretName: horizon-tls
  rules:
    - host: horizon.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: horizon-api
                port:
                  number: 3100
```

::: warning WebSocket timeouts
Set proxy timeouts to at least 300 seconds. Sensor and dashboard WebSocket connections are long-lived and will be dropped by default ingress timeout settings.
:::

## Network Policy

Restrict database access to the Horizon API pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-access
  namespace: horizon
spec:
  podSelector:
    matchLabels:
      role: database
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: horizon-api
      ports:
        - port: 5432
        - port: 8123
        - port: 6379
```

## PostgreSQL

For production, use a managed PostgreSQL service (RDS, Cloud SQL, Azure Database). For self-managed:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: horizon
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
      role: database
  template:
    metadata:
      labels:
        app: postgres
        role: database
    spec:
      containers:
        - name: postgres
          image: postgres:15-alpine
          env:
            - name: POSTGRES_DB
              value: signal_horizon
            - name: POSTGRES_USER
              value: postgres
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: horizon-secrets
                  key: POSTGRES_PASSWORD
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 50Gi
```
