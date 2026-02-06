# Running TestBed Security Testing Scenarios

TestBed (powered by Apparatus) is Signal Horizon's integrated security testing environment. It provides a suite of deliberately vulnerable applications and attack simulation tools that let you validate your Synapse WAF rules, detection coverage, and incident response workflows against realistic threats -- all within a safe, controlled lab.

This tutorial walks through four common testing scenarios, from basic SQL injection to credential stuffing simulation.

## Prerequisites

- Signal Horizon web console access with **Operator** or **Admin** role
- At least one Synapse sensor deployed and connected
- TestBed environment running (see the [TestBed feature overview](../features/testbed.md) for deployment instructions)
- Access to the TestBed dashboard at the configured URL (default: port 8080)

## Understanding the TestBed Architecture

TestBed runs a set of intentionally vulnerable targets behind your Synapse sensor. Traffic flows through the WAF before reaching the target applications, allowing you to observe how your rules respond to real attack payloads.

```
Operator            Synapse Sensor          TestBed Targets
(Browser/CLI)  -->  (WAF Inspection)   -->  (Vulnerable Apps)
                         |
                    Signal Horizon
                    (Alert Dashboard)
```

Key target modules:

| Module | Purpose | Path |
|--------|---------|------|
| Quarterdeck | Banking app with SQL injection flaws | `/victim/login` |
| Guestbook | Reflected XSS endpoint | `/victim/guestbook` |
| DLP Simulator | Generates fake sensitive data | `/dlp?type=cc` |
| Honeypots | Trap endpoints for intrusion detection | `/admin`, `/etc/passwd` |

## Scenario 1: SQL Injection Testing

**Objective**: Validate that your Synapse WAF detects and blocks SQL injection attempts targeting the Quarterdeck banking application.

### Setup

1. Open the Signal Horizon web console.
2. Navigate to **Fleet > Sensors** and confirm your test sensor is online.
3. Open the **TestBed** page from the main navigation.
4. Verify the Quarterdeck module shows a green status indicator.

### Execution

1. From the TestBed dashboard, select **Quarterdeck** and click **Launch Scenario**.
2. Alternatively, send requests manually:

   ```
   GET /victim/login?user=admin'--&pass=anything
   GET /victim/login?user=admin' OR '1'='1&pass=test
   GET /victim/login?user=admin' UNION SELECT * FROM users--&pass=x
   ```

3. Each request passes through the Synapse sensor before reaching the vulnerable endpoint.

### Expected Results

- The Synapse sensor should generate **SQL Injection** alerts visible in Signal Horizon under **Threats > Live Feed**.
- Depending on your rule configuration:
  - **Detect mode**: Alerts appear but traffic passes through. The vulnerable app returns data.
  - **Block mode**: The sensor returns a block page. No data reaches the client.
- The alert detail view should show the matched rule, payload excerpt, and request metadata.

### Cleanup

1. Return to the TestBed dashboard.
2. Click **Reset Scenario** on Quarterdeck to clear session state.
3. Review and close any test alerts in the War Room if they were auto-escalated.

## Scenario 2: XSS Detection Validation

**Objective**: Confirm that cross-site scripting payloads are detected across reflected and stored XSS vectors.

### Setup

1. Ensure the Guestbook module is running in TestBed (check status on the TestBed page).
2. Confirm your WAF rules include XSS detection (navigate to **Fleet > Sensor Config** and verify the `xss` rule category is enabled).

### Execution

1. From TestBed, select **Guestbook** and click **Launch Scenario**.
2. Or submit XSS payloads directly:

   ```
   GET /victim/guestbook?name=<script>alert('xss')</script>
   GET /victim/guestbook?name=<img src=x onerror=alert(1)>
   GET /victim/guestbook?name=<svg onload=alert('xss')>
   ```

3. Test both simple and encoded variants:

   ```
   GET /victim/guestbook?name=%3Cscript%3Ealert(1)%3C/script%3E
   GET /victim/guestbook?name=<scr<script>ipt>alert(1)</script>
   ```

### Expected Results

- Alerts of type **Cross-Site Scripting** should appear in Signal Horizon.
- In block mode, the sensor should return the configured block page.
- Encoded variants test whether your rules handle URL decoding and evasion techniques.
- Review the **payload forensics** detail for each alert to confirm the full decoded payload is captured.

### Cleanup

1. Reset the Guestbook scenario from TestBed.
2. Archive test alerts from the Threats feed.

## Scenario 3: API Abuse Patterns

**Objective**: Test detection of API abuse patterns including enumeration, excessive request rates, and parameter tampering.

### Setup

1. On the TestBed page, ensure the API endpoints module is active.
2. Navigate to **Fleet > Sensor Config** and confirm rate limiting and bot detection rules are enabled on the test sensor.

### Execution

1. **Enumeration attack** -- Cycle through sequential IDs:

   ```
   GET /api/users/1
   GET /api/users/2
   GET /api/users/3
   ...
   GET /api/users/500
   ```

2. **Rate limit testing** -- Send a burst of requests within a short window:

   ```
   for i in $(seq 1 100); do
     curl -s http://testbed-host/api/resource > /dev/null
   done
   ```

3. **Parameter tampering** -- Modify authorization-related parameters:

   ```
   GET /api/account?user_id=OTHER_USER_ID
   POST /api/transfer -d '{"amount": -500}'
   ```

### Expected Results

- **Enumeration**: Signal Horizon should correlate the sequential access pattern and raise a **Suspicious Enumeration** alert after the configured threshold.
- **Rate limiting**: The sensor should begin returning `429 Too Many Requests` after the burst exceeds the rate limit threshold.
- **Parameter tampering**: Alerts should flag the anomalous parameter values. If API intelligence is enabled, schema violations will also appear.

### Cleanup

1. Reset the API module from TestBed.
2. Clear any rate limit blocks on the test sensor by navigating to **Fleet > Sensor Detail** and clicking **Clear Rate Limit State**.

## Scenario 4: Credential Stuffing Simulation

**Objective**: Validate detection of credential stuffing attacks, where an attacker tries many username/password combinations from a breached credential list.

### Setup

1. Ensure the Quarterdeck login endpoint is running.
2. Confirm the **Impossible Travel** and **Brute Force** detection features are enabled in your sensor configuration.
3. From Signal Horizon, navigate to **Settings > Threat Detection** and verify the brute force threshold (default: 10 failed logins in 60 seconds).

### Execution

1. From the TestBed dashboard, select **Credential Stuffing** scenario and click **Launch**.
2. The scenario automatically submits login attempts with varying credentials:

   ```
   POST /victim/login -d 'user=john@example.com&pass=password123'
   POST /victim/login -d 'user=jane@example.com&pass=qwerty'
   POST /victim/login -d 'user=admin@corp.com&pass=admin123'
   ... (continues with 50+ credential pairs)
   ```

3. The simulation rotates source IPs to mimic distributed attacks.

### Expected Results

- A **Brute Force** alert should trigger once the failed login count exceeds the threshold.
- If source IPs are geographically diverse, an **Impossible Travel** alert may also fire.
- The alert timeline in Signal Horizon should show the login attempt frequency and the point at which detection triggered.
- In block mode, subsequent requests from flagged sources should be blocked.

### Cleanup

1. Stop the credential stuffing scenario from TestBed.
2. Navigate to **Fleet > Sensor Detail** and clear any IP blocks that were applied during the test.
3. Review the alerts in the War Room and mark them as **Test Activity**.

## Best Practices

- **Run scenarios during maintenance windows** to avoid confusing test alerts with real threats.
- **Tag test activity** by using a dedicated test tenant or labeling test alerts so they do not pollute production metrics.
- **Start in detect mode** before switching to block mode, so you can verify detection accuracy without interrupting traffic.
- **Review payload forensics** for each scenario to confirm the full attack chain is captured.
- **Schedule regular test runs** (weekly or after rule changes) to validate ongoing detection coverage.

## Troubleshooting

- **TestBed targets not reachable**: Verify the TestBed containers are running and the sensor's upstream configuration points to the correct target host and port.
- **No alerts appearing**: Check that the sensor is connected to Signal Horizon and that the relevant rule categories are enabled. Review the sensor's local logs for processing errors.
- **Alerts fire but action is wrong**: Review the rule action configuration. Rules in `detect` mode will log but not block.

## Next Steps

- [TestBed Feature Overview](../features/testbed.md) -- Architecture and deployment details
- [Synapse Rules](synapse-rules.md) -- Writing custom detection rules
- [War Room Automation](war-room-automation.md) -- Automating incident response for detected threats
- [Payload Forensics](payload-forensics.md) -- Deep inspection of captured attack payloads
