# Feature: Fleet Security Analytics

Fleet Security provides aggregated security analytics across all sensors: protection dashboards, traffic analysis, API catalogs, and threat visibility.

## Protection Dashboard

The Protection Dashboard displays fleet-wide security posture at a glance.

| Metric | Description | Aggregation |
|--------|-------------|-------------|
| **Total RPS** | Requests per second across fleet | Sum |
| **Block Rate** | Percentage of requests blocked | Weighted average |
| **Threat Level** | Current fleet threat assessment | Max severity |
| **Active Campaigns** | Coordinated attacks in progress | Deduplicated count |
| **Sensors Healthy** | Sensors in good state | Count / Total |

## Traffic Analysis

Fleet-wide traffic visibility broken down across six dimensions:

| Dimension | What It Shows |
|-----------|---------------|
| **By Sensor** | Traffic volume per sensor — identify hotspots and load imbalances |
| **By Customer** | Multi-tenant traffic breakdown — per-tenant request volume and block rates |
| **By Endpoint** | API endpoint popularity — most-hit paths, slowest endpoints |
| **By Geography** | Request origin regions — attack source countries, CDN distribution |
| **By Status** | HTTP status distribution — 2xx/3xx/4xx/5xx ratios across the fleet |
| **By Threat** | Attack type breakdown — SQLi vs XSS vs bot vs DLP across sensors |

Each dimension supports time-range filtering and drill-down to individual requests.

## API Catalog

Aggregated view of all APIs discovered by Synapse sensors across the fleet.

| Field | Description |
|-------|-------------|
| **Endpoint Template** | Normalized path pattern (e.g., `/api/users/{id}`) |
| **Methods** | HTTP methods observed (GET, POST, PUT, DELETE) |
| **Request Schema** | Learned JSON schema for request body |
| **Response Schema** | Learned JSON schema for response body |
| **Traffic Volume** | Requests per hour (fleet-wide) |
| **Sensors** | Which sensors see this endpoint |

The API Catalog is built automatically from Synapse's schema learning — no manual API inventory required. New endpoints appear as soon as they receive traffic.

## Accessing Fleet Security

Fleet Security dashboards are in the **Beam** navigation module under **Protection** and **Traffic**.
