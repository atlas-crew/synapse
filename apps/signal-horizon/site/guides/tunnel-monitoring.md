# Tunnel Monitoring

This guide covers the Prometheus metrics exposed by Synapse sensor tunnels, how to set up alerting, and how to troubleshoot connectivity issues between sensors and Signal Horizon.

## Overview

Each Synapse sensor maintains a persistent WebSocket tunnel to Signal Horizon for telemetry, configuration updates, and remote management. The sensor exports tunnel health metrics via its admin endpoint at `/metrics` (default port 6191). These metrics follow the Prometheus exposition format and can be scraped by any Prometheus-compatible system.

## Available Metrics

The following metrics are exported per sensor instance:

| Metric | Type | Description |
|--------|------|-------------|
| `synapse_tunnel_connected` | Gauge | `1` when the tunnel is connected, `0` when disconnected |
| `synapse_tunnel_messages_sent_total` | Counter | Total messages sent through the tunnel |
| `synapse_tunnel_messages_received_total` | Counter | Total messages received through the tunnel |
| `synapse_tunnel_reconnect_attempts_total` | Counter | Number of reconnect attempts since startup |
| `synapse_tunnel_reconnect_delay_ms` | Histogram | Reconnect backoff delay distribution in milliseconds |
| `synapse_tunnel_auth_timeout_total` | Counter | Authentication timeout events |
| `synapse_tunnel_heartbeat_sent_total` | Counter | Heartbeat messages sent to Signal Horizon |
| `synapse_tunnel_heartbeat_timeout_total` | Counter | Heartbeat responses that timed out |
| `synapse_tunnel_channel_buffer_overflow_total` | Counter | Per-channel backpressure events (labeled by `channel`) |
| `synapse_tunnel_handler_latency_ms` | Histogram | Per-channel message handler latency (labeled by `channel`) |

## Prometheus Scrape Configuration

Add a scrape job to your Prometheus configuration targeting each sensor's admin port:

```yaml
scrape_configs:
  - job_name: synapse_tunnel
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
          - sensor-1:6191
          - sensor-2:6191
          - sensor-3:6191
```

If your sensors are behind a service discovery mechanism (Consul, Kubernetes, EC2), use the appropriate `*_sd_configs` instead of `static_configs`.

For sensors behind NAT or firewalls where direct scraping is not possible, use Prometheus Pushgateway or configure the sensor to push metrics to a remote write endpoint.

## Key Metrics to Watch

### Tunnel Connectivity

The most important metric is `synapse_tunnel_connected`. A value of `0` means the sensor cannot communicate with Signal Horizon -- no telemetry, no configuration updates, no remote management.

```promql
# Sensors currently disconnected
synapse_tunnel_connected == 0
```

### Reconnect Behavior

When a tunnel disconnects, the sensor uses exponential backoff to reconnect. Monitor the P95 reconnect delay to detect persistent connectivity problems:

```promql
# P95 reconnect delay over 5 minutes
histogram_quantile(0.95, sum by (le) (rate(synapse_tunnel_reconnect_delay_ms_bucket[5m])))
```

A rising reconnect delay indicates the sensor is struggling to re-establish the tunnel. Common causes include network instability, Signal Horizon being unreachable, or authentication failures.

### Channel Backpressure

Each tunnel multiplexes several message channels (telemetry, commands, heartbeats). If a channel's consumer cannot keep up, the buffer overflows:

```promql
# Buffer overflow rate by channel
rate(synapse_tunnel_channel_buffer_overflow_total[5m])
```

Sustained buffer overflows on the telemetry channel may indicate that Signal Horizon is under load or that the sensor is generating telemetry faster than it can be transmitted.

### Handler Latency

Track how long it takes each channel to process incoming messages:

```promql
# P95 handler latency by channel
histogram_quantile(0.95, sum by (le, channel) (rate(synapse_tunnel_handler_latency_ms_bucket[5m])))
```

High latency on the command channel may slow down configuration pushes and remote shell sessions.

## Alerting Rules

Configure alerts for the most critical tunnel conditions:

| Alert | Expression | Duration | Severity |
|-------|-----------|----------|----------|
| TunnelDisconnected | `synapse_tunnel_connected == 0` | 5m | warning |
| TunnelReconnectDelayHigh | P95 reconnect delay > 30s | 10m | warning |
| TunnelBufferOverflow | `increase(synapse_tunnel_channel_buffer_overflow_total[5m]) > 0` | 5m | warning |
| TunnelHeartbeatTimeout | `increase(synapse_tunnel_heartbeat_timeout_total[10m]) > 3` | 5m | critical |

Example Prometheus alert rule for the most critical case:

```yaml
groups:
  - name: synapse-tunnel
    rules:
      - alert: TunnelDisconnected
        expr: synapse_tunnel_connected == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Sensor tunnel disconnected"
```

## Grafana Dashboard

Build a dashboard with these panels for complete tunnel visibility:

| Panel | Type | PromQL |
|-------|------|--------|
| Tunnel Connected | Stat | `synapse_tunnel_connected` |
| Reconnect Delay P95 | Time Series | `histogram_quantile(0.95, sum by (le) (rate(synapse_tunnel_reconnect_delay_ms_bucket[5m])))` |
| Buffer Overflow by Channel | Time Series | `rate(synapse_tunnel_channel_buffer_overflow_total[5m])` |
| Handler Latency P95 | Time Series | `histogram_quantile(0.95, sum by (le, channel) (rate(synapse_tunnel_handler_latency_ms_bucket[5m])))` |
| Message Throughput | Time Series | `rate(synapse_tunnel_messages_sent_total[5m])` / `rate(synapse_tunnel_messages_received_total[5m])` |

For the Tunnel Connected stat panel, use value mappings: `1 = Connected (green)`, `0 = Disconnected (red)`. For channel-labeled panels, use `{{channel}}` as the legend format.

## Troubleshooting Connectivity Issues

### Sensor Shows Disconnected

1. Verify the sensor process is running: `systemctl status synapse`
2. Check the tunnel metric locally: `curl -s http://localhost:6191/metrics | grep synapse_tunnel_connected`
3. Review sensor logs: `journalctl -u synapse -n 50 --no-pager | grep -i tunnel`

### Frequent Reconnects

If `synapse_tunnel_reconnect_attempts_total` is climbing rapidly:

1. Check network stability between the sensor and Signal Horizon.
2. Look for auth timeouts (`synapse_tunnel_auth_timeout_total` increasing).
3. Verify the sensor API key has not expired in **Fleet > Sensor Keys**.
4. Check if a firewall or proxy is terminating idle WebSocket connections.

### High Handler Latency

1. Check sensor CPU and memory -- the sensor may be overloaded.
2. Review the number of active channels and message rates.
3. Look for disk I/O contention if writing telemetry to local storage.

### Auth Timeout Spikes

1. Verify the sensor API key is valid in **Fleet > Sensor Keys**.
2. Check that Signal Horizon API is healthy and accepting connections.
3. Ensure clocks are synchronized (NTP) -- JWT validation is time-sensitive.
