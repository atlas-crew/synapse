# Blue/Green Deployments

This guide explains how to use blue/green deployments to push WAF rule updates to your Synapse sensor fleet with zero downtime and instant rollback capability.

## What Are Blue/Green Deployments?

In a blue/green deployment, your sensors maintain two rule slots:

- **Blue**: The currently active rule set serving live traffic.
- **Green**: A staged rule set that has been loaded but is not yet active.

Signal Horizon orchestrates a two-phase process: first, the new rules are staged to all target sensors (green). Once every sensor confirms the rules are loaded and ready, Signal Horizon sends an atomic switch command that activates the green rules fleet-wide. The old blue rules remain available for instant rollback.

This approach eliminates the window of inconsistency that occurs when rules are pushed to sensors one at a time.

## When to Use Blue/Green

Blue/green is the recommended strategy when:

- You need **all sensors to switch simultaneously** to a new rule set.
- You want the ability to **roll back instantly** if the new rules cause problems.
- You are deploying to a **large fleet** where staggered updates would create inconsistent protection.
- Compliance requires a **verifiable deployment record** with staging and activation timestamps.

For smaller changes or testing, consider the `rolling` or `canary` strategies instead.

## Deployment Lifecycle

A blue/green deployment progresses through these phases:

1. **Staging** -- Rules are pushed to all target sensors with `activate: false`. Each sensor loads the rules into its green slot.
2. **Staged** -- All sensors (or a configured minimum percentage) have confirmed the rules are loaded. The deployment is ready to activate.
3. **Switching** -- Signal Horizon broadcasts the activation command. All sensors atomically swap green to active.
4. **Active** -- The green rules are now serving traffic. The old blue rules remain loaded for rollback.
5. **Retired** -- After a configurable delay, the old blue rules are cleaned up.

If any phase fails, the deployment moves to a **Failed** state and the green rules are aborted on all sensors, leaving the blue (current) rules in place.

## Starting a Blue/Green Deployment

### From the Dashboard

1. Navigate to **Fleet > Rules**.
2. Select the rules you want to deploy.
3. Choose the target sensors (or sensor groups).
4. Under **Strategy**, select **Blue/Green**.
5. Configure the deployment options (see below).
6. Click **Deploy**.

### From the API

```bash
curl -X POST "https://<signal-horizon>/api/fleet/rules/push" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ruleIds": ["sql-injection-001", "xss-reflect-002", "cmd-inject-001"],
    "sensorIds": ["sensor-east-1", "sensor-east-2", "sensor-west-1"],
    "strategy": "blue_green",
    "stagingTimeout": 120000,
    "switchTimeout": 30000,
    "requireAllSensorsStaged": true,
    "cleanupDelayMs": 300000
  }'
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `stagingTimeout` | number (ms) | 60000 | Maximum time to wait for all sensors to confirm staging |
| `switchTimeout` | number (ms) | 30000 | Maximum time to wait for the atomic switch to complete |
| `requireAllSensorsStaged` | boolean | true | Whether 100% of sensors must stage before switching |
| `minStagedPercentage` | number (1-100) | 100 | Minimum percentage of sensors that must stage (when `requireAllSensorsStaged` is false) |
| `cleanupDelayMs` | number (ms) | 300000 | Delay before cleaning up the retired blue deployment |

### Relaxing Staging Requirements

In some environments, a small number of sensors may be temporarily unreachable. To proceed with the switch when most sensors are ready:

```json
{
  "strategy": "blue_green",
  "requireAllSensorsStaged": false,
  "minStagedPercentage": 90
}
```

This allows the switch to proceed when 90% of target sensors have staged. Sensors that did not stage remain on their existing rules and will not participate in the switch.

## Monitoring Deployment Health

### Deployment Status

Check the status of an active deployment:

```bash
curl "https://<signal-horizon>/api/fleet/deployments/<deployment-id>" \
  -H "Authorization: Bearer $API_TOKEN"
```

The response includes:
- Overall deployment status (`staging`, `staged`, `switching`, `active`, `failed`)
- Per-sensor staging and activation status
- Timestamps for each phase transition

### What to Watch During Staging

- **Sensor staging status**: Each sensor reports `pending`, `staged`, or `failed`.
- **Staging progress**: The percentage of sensors that have confirmed.
- **Timeout countdown**: If sensors are slow to stage, you may need to increase `stagingTimeout`.

### What to Watch After Activation

After the switch completes, monitor these indicators:

- **WAF event rates**: A sudden spike in blocks or a drop to zero may indicate a rule problem.
- **Sensor health**: Check CPU, memory, and latency on sensors in the fleet dashboard.
- **Error rates**: Monitor your upstream application error rates for unexpected changes.

## Rolling Back

If the new rules cause issues after activation, you can roll back by deploying the previous rule set using the same blue/green process. Signal Horizon retains the old blue rules on each sensor for the duration of the `cleanupDelayMs` window.

To roll back quickly:

1. Navigate to **Fleet > Deployments** and locate the active deployment.
2. Click **Rollback** to revert all sensors to the previous rule set.

Alternatively, deploy the previous rules via the API with the `immediate` strategy for the fastest rollback:

```bash
curl -X POST "https://<signal-horizon>/api/fleet/rules/push" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ruleIds": ["<previous-rule-ids>"],
    "sensorIds": ["sensor-east-1", "sensor-east-2", "sensor-west-1"],
    "strategy": "immediate"
  }'
```

## Best Practices

### Pre-deployment

- **Test rules in shadow mode** on a staging sensor before deploying to the full fleet. See the [Tuning WAF Rules](tuning-waf-rules.md) guide.
- **Deploy to a canary group first** using the `canary` strategy. Once validated, use blue/green for the remaining fleet.
- **Schedule during low-traffic windows** when possible, even though blue/green is zero-downtime.

### During Deployment

- **Watch the staging phase carefully**. If sensors fail to stage, investigate before proceeding.
- **Do not increase `minStagedPercentage` above what your fleet can reliably achieve**. A failed deployment is safer than a partial switch.
- **Keep the cleanup delay generous** (at least 5 minutes). This preserves your rollback window.

### Post-deployment

- **Monitor for at least 15 minutes** after activation before considering the deployment complete.
- **Compare WAF metrics** (block rate, challenge rate, allowed traffic) before and after the deployment.
- **Document the deployment** in your change management system with the deployment ID and timestamps.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Staging timeout | One or more sensors unreachable | Check sensor connectivity; increase `stagingTimeout` or lower `minStagedPercentage` |
| Switch timeout | Sensors not acknowledging activation | Verify sensor tunnel connections; check handler latency metrics |
| Deployment failed immediately | Invalid rule IDs or sensor ownership mismatch | Verify rule IDs exist and sensors belong to your tenant |
| Rules not taking effect after switch | Sensor not processing the activation command | Check sensor logs; verify the deployment status shows `active` |
| Cannot roll back | Cleanup delay expired | Redeploy the previous rules using `immediate` strategy |
