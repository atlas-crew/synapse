# Creating Custom DLP Patterns

Data Loss Prevention (DLP) patterns allow Signal Horizon to detect and block sensitive data before it leaves your network. While built-in patterns cover common formats like credit card numbers, Social Security numbers, and API keys, most organizations need custom patterns to protect proprietary data unique to their environment.

This tutorial walks through creating, testing, and deploying a custom DLP pattern from scratch.

## Prerequisites

- Access to the Signal Horizon web console with **Operator** or **Admin** role
- At least one Synapse sensor connected and reporting
- Familiarity with regular expressions (regex)

## Step 1: Understanding Pattern Syntax

DLP patterns in Signal Horizon use standard regular expressions with a few extensions for performance and accuracy.

Each pattern definition includes:

| Field | Description |
|-------|-------------|
| `name` | Human-readable label displayed in alerts |
| `pattern` | The regex that matches sensitive data |
| `category` | Grouping for reporting (e.g., `pii`, `financial`, `internal`) |
| `severity` | Alert priority: `low`, `medium`, `high`, or `critical` |
| `action` | What happens on match: `log`, `redact`, or `block` |
| `context_window` | Number of surrounding characters included in match context (default: 50) |

Patterns are evaluated against HTTP response bodies, request bodies, and selected headers. They run on the sensor itself, so matches are detected at the edge before data reaches external networks.

## Step 2: Creating a Custom Pattern

Suppose your organization uses internal employee IDs in the format `EMP-` followed by six digits (e.g., `EMP-041893`). If this identifier appears in an API response, it likely indicates a data leak.

1. Navigate to **Fleet > DLP Configuration** in the web console.
2. Click **Add Custom Pattern**.
3. Fill in the pattern details:

   - **Name**: Internal Employee ID
   - **Pattern**: `EMP-\d{6}`
   - **Category**: `internal`
   - **Severity**: `high`
   - **Action**: `redact`

4. Optionally add a **validation function** to reduce false positives. For example, you can add a Luhn check or range constraint:

   - **Min match length**: 10
   - **Boundary mode**: `word` (requires word boundaries around the match)

5. Click **Save as Draft**. The pattern is saved but not yet active on any sensor.

## Step 3: Testing in Shadow Mode

Before enforcing a new pattern in production, deploy it in **shadow mode**. Shadow mode evaluates the pattern against live traffic but only logs matches without taking any blocking or redaction action.

1. From the DLP Configuration page, locate your draft pattern.
2. Click the toggle icon to set the mode to **Shadow**.
3. Under **Scope**, select the sensors or sensor groups to test against.
4. Click **Deploy Shadow**.

The pattern is now pushed to the selected sensors. Monitor results in the **DLP Matches** dashboard:

- Navigate to **Fleet > DLP Dashboard**.
- Filter by pattern name or category.
- Review each match to confirm it is a true positive.

Spend at least 24-48 hours in shadow mode to build confidence in the pattern. If you see false positives, refine the regex or add boundary constraints, then redeploy.

## Step 4: Deploying to Production

Once you are confident the pattern is accurate:

1. Return to **Fleet > DLP Configuration**.
2. Select your pattern and click **Promote to Active**.
3. Choose the enforcement action:
   - **Log**: Record the match but allow the traffic to pass.
   - **Redact**: Replace matched content with `[REDACTED]` in the response.
   - **Block**: Drop the response entirely and return a configured error page.
4. Select the target sensor scope (individual sensors, groups, or fleet-wide).
5. Click **Deploy**.

The pattern is now live. Sensors will begin enforcing the configured action immediately upon receiving the updated configuration.

## Step 5: Monitoring Pattern Matches

After deployment, monitor pattern performance from the DLP Dashboard:

- **Match volume**: Sudden spikes may indicate a new data exposure path.
- **False positive rate**: Track patterns you manually dismiss to identify tuning needs.
- **Sensor coverage**: Confirm all intended sensors are running the latest pattern set.

Set up alert rules to notify your team when high-severity patterns trigger:

1. Navigate to **Settings > Alert Rules**.
2. Create a new rule with condition: `dlp.pattern.severity = high AND dlp.matches > 0`.
3. Configure the notification channel (email, Slack, webhook).

## Example Patterns

### Custom Employee IDs

```
Name:     Internal Employee ID
Pattern:  \bEMP-\d{6}\b
Category: internal
Severity: high
```

### Medical Record Numbers

Organizations handling health data often use MRN formats like `MRN` followed by 8-10 digits:

```
Name:     Medical Record Number
Pattern:  \bMRN\d{8,10}\b
Category: pii
Severity: critical
```

### Internal Project Codes

If your company uses project codes in the format `PRJ-` followed by a department abbreviation and four digits (e.g., `PRJ-ENG-2847`):

```
Name:     Internal Project Code
Pattern:  \bPRJ-[A-Z]{2,5}-\d{4}\b
Category: internal
Severity: medium
```

### Multi-Pattern Strategy

For comprehensive protection, combine multiple patterns within a single DLP policy. Group related patterns under the same category so operators can manage them together and review matches in context.

## Troubleshooting

- **Pattern not matching expected content**: Verify boundary modes. Word boundary (`\b`) requires non-word characters on both sides of the match.
- **Too many false positives**: Tighten the regex or add length constraints. Consider whether boundary mode or context validation can filter noise.
- **Pattern not deployed to sensor**: Check the sensor's config sync status under **Fleet > Sensors**. A pending sync indicates the sensor has not yet received the update.

## Next Steps

- [DLP Protection](../features/dlp-protection.md) -- Feature overview and architecture
- [Synapse Configuration Reference](../reference/synapse-configuration.md) -- Full sensor configuration schema
- [Fleet Configuration Management](fleet-configuration-management.md) -- Pushing configuration updates fleet-wide
