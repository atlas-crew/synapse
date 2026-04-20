# WAF Match Kinds Reference

This reference lists all available `MatchCondition` kinds and their options for the Synapse WAF engine.

## Structural Filters

| Kind | Option | Description |
|------|--------|-------------|
| `method` | `match` (string) | Matches HTTP method (GET, POST, etc.). |
| `uri` | `match` (Condition) | Evaluates the URI path. |
| `args` | `match` (Condition) | Evaluates the full query string. |
| `named_argument` | `name` (string), `match` (Condition) | Evaluates a specific query parameter. |
| `header` | `name` (string), `match` (Condition) | Evaluates a specific HTTP header. |
| `request_json` | `match` (Condition) | Evaluates the request body if it's JSON. |
| `static_content` | `match` (boolean) | Matches based on static asset detection. |

## Logical Operators

| Kind | Option | Description |
|------|--------|-------------|
| `boolean` | `op` ("and", "or"), `match` (Array of Conditions) | Logical grouping of multiple conditions. |

## Predicates

| Kind | Option | Description |
|------|--------|-------------|
| `contains` | `match` (string) | Substring match. |
| `equals` | `match` (string/number) | Exact match. |
| `starts_with` | `match` (string) | Prefix match. |
| `regex` | `match` (string) | Regular expression match. |
| `word` | `match` (string) | Case-insensitive whole-word match (e.g., `\bword\b`). |
| `compare` | `op` (eq, gt, lt, gte, lte), `match` (number) | Numerical comparison. |

## Transformations

Always nest these to transform data before evaluation.

| Kind | Option | Description |
|------|--------|-------------|
| `to_lowercase` | `match` (Condition) | Converts value to lowercase. |
| `percent_decode` | `match` (Condition) | Decodes URL percent-encoding. |
| `decode_if_base64` | `match` (Condition) | Decodes Base64 if a valid pattern is detected. |

## Analyzers

Built-in security heuristics.

| Kind | Option | Description |
|------|--------|-------------|
| `sql_analyzer` | `severity` (high, med, low) | Heuristic SQLi detection. |
| `xss_analyzer` | `severity` (high, med, low) | Heuristic XSS detection. |
| `cmd_analyzer` | `severity` (high, med, low) | Heuristic OS command injection detection. |
| `path_traversal_analyzer` | `severity` (high, med, low) | Heuristic directory traversal detection. |

## Advanced

| Kind | Option | Description |
|------|--------|-------------|
| `ja4` | `match` (string/regex) | Matches JA4 client fingerprint. |
| `ja4h` | `match` (string/regex) | Matches JA4H HTTP client fingerprint. |
| `dlp_violation` | `violation_kind` (string) | Matches specific DLP violations (deferred pass only). |
| `schema_violation` | `match` (Condition) | Matches schema validation failures. |
