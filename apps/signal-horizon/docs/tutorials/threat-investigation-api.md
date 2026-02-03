# Threat Investigation with the Signal-Horizon API

This tutorial walks through a practical workflow for investigating threats using
Signal Horizon's REST APIs. You will pull recent block decisions, pivot into
detail, and run timeline hunts to correlate signals across your tenant.

## Objectives

- Retrieve recent block decisions from the Beam threats API.
- Inspect a single block decision in detail.
- Run a hunt query to correlate related signals over time.
- (Optional) Perform cross-tenant IP activity checks as an admin.
- Save and re-run queries for repeatable investigations.

## Prerequisites

- API key with `dashboard:read` scope (for `/api/v1/beam/*` endpoints).
- Network access to the Signal Horizon API.
- `curl` and `jq` installed.

Set your API base URL and key:

```bash
export SH_API_BASE="https://your-signal-horizon.com"
export SH_API_KEY="sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Step 1: List Recent Threats (Beam)

Fetch recent block decisions with filters for severity and time range:

```bash
curl -s "$SH_API_BASE/api/v1/beam/threats?severity=high&timeRange=24h&limit=20" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Accept: application/json" | jq .
```

Expected fields:

- `blocks`: Array of block decisions.
- `pagination.total`: Total count of decisions.
- `pagination.hasMore`: Whether more results exist.

Checkpoint:
- You should see `blocks` populated and `pagination.total` > 0 if threats exist.

## Step 2: Pivot into a Single Threat

Extract the first block ID and fetch full details:

```bash
export BLOCK_ID=$(
  curl -s "$SH_API_BASE/api/v1/beam/threats?limit=1" \
    -H "Authorization: Bearer $SH_API_KEY" \
    -H "Accept: application/json" | jq -r '.blocks[0].id'
)

curl -s "$SH_API_BASE/api/v1/beam/threats/$BLOCK_ID" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Accept: application/json" | jq .
```

Checkpoint:
- The response includes a `block` object with sensor metadata and decision fields.

## Step 3: Run a Timeline Hunt (Correlate Signals)

Use the Hunt API to search a time window for related signals:

```bash
curl -s "$SH_API_BASE/api/v1/hunt/query" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "startTime": "2026-02-01T00:00:00Z",
    "endTime": "2026-02-02T00:00:00Z",
    "signalTypes": ["BLOCK", "ALERT", "ANOMALY"],
    "severities": ["HIGH", "CRITICAL"],
    "minConfidence": 0.7,
    "limit": 200
  }' | jq .
```

Expected fields:

- `success`: `true` when query succeeded.
- `data`: List of matched signals.
- `meta.source`: `postgres` or `clickhouse` depending on availability.

Checkpoint:
- `data` returns signals within your time range and tenant.

## Step 4 (Optional): Cross-Tenant IP Activity (Admin Only)

If you have admin privileges, check whether a source IP appears across tenants:

```bash
curl -s "$SH_API_BASE/api/v1/hunt/ip-activity" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "sourceIp": "203.0.113.45",
    "days": 14
  }' | jq .
```

Checkpoint:
- `data` returns activity clusters and `meta.lookbackDays` matches your request.

## Step 5: Save and Re-Run a Hunt Query

Create a saved query for repeatable investigations:

```bash
curl -s "$SH_API_BASE/api/v1/hunt/saved-queries" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High severity last 24h",
    "description": "Critical/high signals in the last day",
    "query": {
      "startTime": "2026-02-01T00:00:00Z",
      "endTime": "2026-02-02T00:00:00Z",
      "severities": ["HIGH", "CRITICAL"],
      "limit": 500
    }
  }' | jq .
```

Re-run the saved query:

```bash
export QUERY_ID="<saved-query-id>"

curl -s "$SH_API_BASE/api/v1/hunt/saved-queries/$QUERY_ID/run" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Accept: application/json" | jq .
```

## Step 6: Export Findings

Capture results for external analysis:

```bash
curl -s "$SH_API_BASE/api/v1/beam/threats?timeRange=7d&limit=100" \
  -H "Authorization: Bearer $SH_API_KEY" \
  -H "Accept: application/json" > beam-threats-7d.json
```

## Troubleshooting

- **401/403**: Ensure the API key is valid and includes `dashboard:read` scope.
- **400 Invalid query parameters**: Check `startTime`/`endTime` ISO format and value types.
- **503 (ClickHouse disabled)**: Historical Hunt endpoints fall back to Postgres or return 503 when ClickHouse is off.
- **Empty results**: Expand `timeRange` or remove filters to validate data flow.

## Next Steps

- [Rule Authoring Flow](../guides/rule-authoring-flow.md)
- [API Key Management](./api-key-management.md)
- [War Room Automation](./war-room-automation.md)
