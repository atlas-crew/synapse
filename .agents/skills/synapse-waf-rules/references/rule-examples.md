# WAF Rule Examples

Common security policies for the Synapse WAF engine.

## 1. Access Control: JA4 Fingerprint Required

Block access to `/admin` if the client's JA4 fingerprint doesn't match a known-safe baseline.

```json
{
  "id": 2001,
  "description": "Block unauthorized JA4 on admin",
  "risk": 100.0,
  "blocking": true,
  "matches": [
    { "type": "uri", "match": { "type": "starts_with", "match": "/admin" } },
    { "type": "ja4", "match": { "type": "regex", "match": "^(?!t13d151617.*$)" } }
  ]
}
```

## 2. SQL Injection: Parameter-Level Detection

Heuristic detection in query arguments with automatic URL decoding.

```json
{
  "id": 1002,
  "description": "SQLi in query arguments",
  "risk": 40.0,
  "blocking": true,
  "matches": [
    {
      "type": "args",
      "match": {
        "type": "percent_decode",
        "match": {
          "type": "sql_analyzer",
          "severity": "high"
        }
      }
    }
  ]
}
```

## 3. SSRF: Metadata Endpoint Guard

Block attempts to reach AWS/GCP/Azure metadata services.

```json
{
  "id": 3001,
  "description": "SSRF Cloud Metadata Guard",
  "risk": 100.0,
  "blocking": true,
  "matches": [
    {
      "type": "args",
      "match": {
        "type": "regex",
        "match": "(?i)169\\.254\\.169\\.254|metadata\\.google\\.internal|instance-data\\.ec2\\.internal"
      }
    }
  ]
}
```

## 4. DLP: Data Loss Prevention (Deferred Pass)

Detect sensitive data (e.g., credit cards) in request bodies.

```json
{
  "id": 4001,
  "description": "Block Credit Card Leakage",
  "risk": 80.0,
  "blocking": true,
  "matches": [
    { "type": "dlp_violation", "violation_kind": "credit_card" }
  ]
}
```

## 5. Logical AND: Combined Conditions

Multiple required conditions for a rule to fire.

```json
{
  "id": 5001,
  "description": "Restrict POST to /api with specific Header",
  "risk": 50.0,
  "blocking": true,
  "matches": [
    { "type": "method", "match": "POST" },
    { "type": "uri", "match": { "type": "starts_with", "match": "/api" } },
    { "type": "header", "name": "X-Custom-Auth", "match": { "type": "equals", "match": "secret-value" } }
  ]
}
```
