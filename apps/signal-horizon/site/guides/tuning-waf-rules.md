# Tuning WAF Rules

This guide explains how to adjust WAF rule thresholds and overrides on your Synapse sensors to balance security with operational needs. Whether you are reducing false positives for a partner integration or tightening protection on an API endpoint, the steps below apply.

## How WAF Thresholds Work

Every request processed by a Synapse sensor receives a **risk score** between 0 and 100. The sensor evaluates the request against all enabled WAF rules, and each matching rule contributes to the cumulative score. The sensor then compares the final score against a **threshold**:

- If the score meets or exceeds the threshold, the request is blocked (or challenged, depending on the default action).
- If the score falls below the threshold, the request is allowed through.

A **lower threshold** means more requests are blocked (higher sensitivity). A **higher threshold** means fewer requests are blocked (lower sensitivity).

| Threshold | Sensitivity | Typical Use Case |
|-----------|-------------|-----------------|
| 40-50 | High | API endpoints, admin panels |
| 60-70 | Medium | Standard web applications |
| 80-90 | Low | Legacy integrations, partner traffic |

## Adjusting the Global Threshold

The global threshold applies to all sites on a sensor unless overridden. Open the sensor configuration in Signal Horizon under **Fleet > Sensors > [Sensor] > Configuration**, or edit the sensor config file directly:

```yaml
server:
  waf_enabled: true
  waf_threshold: 70
```

- `waf_enabled` must be `true` for any WAF processing to occur.
- `waf_threshold` sets the baseline for all sites handled by this sensor.

Start with a threshold of 70 if you are unsure. You can tune it lower after reviewing blocked and allowed traffic in the dashboard.

## Per-Site Rule Overrides

Different sites often need different sensitivity levels. A public marketing site may tolerate a higher threshold, while an API serving financial data needs stricter protection.

Override the threshold for a specific hostname in the site configuration:

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "10.0.0.10"
        port: 8080
    waf:
      enabled: true
      threshold: 50
```

This site now blocks requests at a risk score of 50, regardless of the global threshold.

### Overriding Individual Rules

You can change the action for specific rules on a per-site basis. Available actions are:

| Action | Behavior |
|--------|----------|
| `block` | Immediately block the request |
| `log` | Allow the request but log the match |
| `allow` | Suppress the rule entirely for this site |
| `challenge` | Present a CAPTCHA or JavaScript challenge |

Example configuration with multiple overrides:

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "10.0.0.10"
        port: 8080
    waf:
      enabled: true
      threshold: 75
      rule_overrides:
        sql-injection-001: "block"
        noisy-header-019: "log"
        legacy-partner-003: "allow"
```

Find rule IDs in the **Hunting** or **WAF Events** sections of the Signal Horizon dashboard, or in the telemetry feed for your sensor.

## Testing Changes in Shadow Mode

Before applying threshold or rule changes in production, validate them using shadow mode. Shadow mode evaluates rules and records decisions without enforcing them.

1. Set the site WAF mode to `shadow`:

```yaml
sites:
  - hostname: "api.example.com"
    waf:
      enabled: true
      mode: "shadow"
      threshold: 50
```

2. Reload the sensor configuration:

```bash
curl -X POST "http://<sensor-admin>:6191/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

3. Monitor the WAF telemetry in Signal Horizon. Shadow decisions appear in the event feed tagged with `mode: shadow`.

4. Review the results. Look for:
   - Legitimate traffic that would have been blocked (false positives)
   - Malicious traffic that would have been missed (false negatives)

5. When satisfied, switch the mode back to `enforce` and reload.

## Common Tuning Scenarios

### Reducing False Positives

If legitimate requests are being blocked:

1. Navigate to **Hunting > WAF Events** and filter for blocked requests on the affected site.
2. Identify the rule IDs causing false positives.
3. Set those rules to `log` on the affected site to stop blocking while you investigate:

```yaml
rule_overrides:
  noisy-header-019: "log"
  form-encoding-042: "log"
```

4. If the rule is consistently wrong for this site, set it to `allow`. If it fires occasionally on edge cases, keep it on `log` and raise the site threshold slightly.

### Tightening Protection for APIs

API endpoints typically need stricter protection because they lack browser-based defenses (cookies, CAPTCHA):

1. Lower the threshold to 40-50 for API sites.
2. Set injection rules (`sql-injection-*`, `command-injection-*`) to `block` explicitly.
3. Enable `challenge` action only if your API clients can handle challenge responses; otherwise use `block`.

```yaml
sites:
  - hostname: "api.internal.example.com"
    waf:
      enabled: true
      threshold: 45
      rule_overrides:
        sql-injection-001: "block"
        sql-injection-002: "block"
        command-injection-001: "block"
```

### Handling Partner or Legacy Traffic

Some partners send traffic that triggers WAF rules due to unusual headers or encoding. Identify the partner's traffic patterns, override the specific noisy rules to `allow` for the partner site, and keep the global threshold intact.

## Applying Configuration Changes

After editing any WAF settings, reload the sensor to apply changes without downtime:

```bash
curl -X POST "http://<sensor-admin>:6191/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

You can also push changes from Signal Horizon via **Fleet > Sensors > [Sensor] > Push Config**.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Unexpected blocks | Threshold too low or noisy rule | Raise per-site threshold or override rule to `log` |
| No blocks at all | `waf_enabled` is false or threshold too high | Verify WAF is enabled; lower threshold |
| Reload fails | YAML syntax error or invalid admin key | Validate YAML; check `X-Admin-Key` |
| Shadow events not appearing | Mode not set or telemetry not connected | Confirm `mode: shadow` and sensor tunnel is online |
