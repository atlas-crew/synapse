# Synapse API Reference

Fleet-wide snapshot routes live at the non-sensor-prefixed `/api/v1/synapse/*` paths. They return the latest stored payload snapshot per sensor, plus a partial-results envelope so dashboards can keep rendering when some sensors are missing fresh data.

If every sensor fails for a fleet route, Horizon still returns the same envelope, but includes a top-level `error` object so dashboards can distinguish full data absence from partial degradation.

## Fleet Snapshot Routes

### GET `/api/v1/synapse/dlp/stats`
Returns aggregate DLP counters from `SensorPayloadSnapshot.stats.dlp`.

### GET `/api/v1/synapse/dlp/violations`
Returns aggregate DLP violations across the fleet. Supports `?limit=`.

### GET `/api/v1/synapse/payload/stats`
Returns aggregate payload summary counters from the latest snapshot per sensor.

### GET `/api/v1/synapse/payload/endpoints`
Returns merged endpoint summaries across the fleet. Supports `?limit=`.

### GET `/api/v1/synapse/payload/anomalies`
Returns merged payload anomalies across the fleet. Supports `?limit=`.

### GET `/api/v1/synapse/payload/bandwidth`
Returns merged payload bandwidth totals and time buckets across the fleet.

## Response Envelope

    {
      "aggregate": {},
      "results": [
        { "sensorId": "sen_123", "status": "ok", "data": {} },
        { "sensorId": "sen_456", "status": "error", "error": "No payload snapshot available" }
      ],
      "summary": { "succeeded": 1, "failed": 1 },
      "error": { "code": "FLEET_PAYLOAD_STATS_UNAVAILABLE", "message": "No sensors reported a usable payload snapshot" }
    }

## Sensor-Scoped Diagnostic Routes

The existing `/:sensorId/*` routes stay in place for drill-down and sensor-detail views:

- `/api/v1/synapse/:sensorId/proxy/_sensor/dlp/stats`
- `/api/v1/synapse/:sensorId/proxy/_sensor/dlp/violations`
- `/api/v1/synapse/:sensorId/payload/stats`
- `/api/v1/synapse/:sensorId/payload/endpoints`
- `/api/v1/synapse/:sensorId/payload/anomalies`
- `/api/v1/synapse/:sensorId/payload/bandwidth`

Treat those sensor-prefixed routes as diagnostic/detail surfaces. Fleet dashboards should prefer the aggregate routes above.
