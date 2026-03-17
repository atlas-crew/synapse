# Tunnel Metrics

Tunnel health metrics are exported via the sensor admin `/metrics` endpoint. Each sensor exposes its own metrics stream, so per-sensor visibility comes from scraping each sensor instance.

## Metric Catalog
- `synapse_tunnel_connected` (gauge) 1 when the tunnel is connected.
- `synapse_tunnel_messages_sent_total` (counter) Total tunnel messages sent.
- `synapse_tunnel_messages_received_total` (counter) Total tunnel messages received.
- `synapse_tunnel_reconnect_attempts_total` (counter) Reconnect attempts.
- `synapse_tunnel_reconnect_delay_ms` (histogram) Reconnect backoff delay in milliseconds.
- `synapse_tunnel_auth_timeout_total` (counter) Auth timeouts.
- `synapse_tunnel_heartbeat_sent_total` (counter) Heartbeats sent.
- `synapse_tunnel_heartbeat_timeout_total` (counter) Heartbeat timeouts.
- `synapse_tunnel_channel_buffer_overflow_total{channel=...}` (counter) Per-channel backpressure events.
- `synapse_tunnel_handler_latency_ms{channel=...}` (histogram) Per-channel handler latency in milliseconds.

## Scrape Config
Sample Prometheus scrape job:
- `apps/synapse-pingora/docs/observability/tunnel-prometheus-scrape.yml`

## Alert Rules
Sample alert rules:
- `apps/synapse-pingora/docs/observability/tunnel-alerts.yml`

## Grafana Dashboard
Sample dashboard JSON:
- `apps/synapse-pingora/docs/observability/tunnel-grafana-dashboard.json`
