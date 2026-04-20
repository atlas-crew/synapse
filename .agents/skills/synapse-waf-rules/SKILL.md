---
name: synapse-waf-rules
description: Author, validate, and test WAF rules for the Synapse Pingora security engine. Use when creating or modifying rules in apps/synapse-pingora/config.yaml or other WAF rule JSON/YAML files.
---

# Synapse WAF Rule Architecture

This skill provides the procedural knowledge required to author high-performance, error-free WAF rules for the Synapse engine.

## Rule Structure

A `WafRule` consists of metadata and a collection of `MatchCondition` objects. All conditions must match for the rule to fire.

```json
{
  "id": 1001,
  "description": "Detect SQL Injection in Query Args",
  "risk": 25.0,
  "blocking": true,
  "matches": [
    {
      "type": "args",
      "match": {
        "type": "sql_analyzer",
        "severity": "high"
      }
    }
  ]
}
```

## Bundled Utilities

- **`scripts/validate_rules.cjs`**: Validates rules against the project's Rust schema (required fields, numeric IDs, valid match kinds).
  - Usage: `node scripts/validate_rules.cjs <file.json|yaml>`

## Core Match Kinds

- **Structural**: `uri`, `method`, `header`, `args`, `named_argument`, `request_json`.
- **Transformation**: `to_lowercase`, `percent_decode`, `decode_if_base64`.
- **Predicates**: `contains`, `equals`, `starts_with`, `regex`, `word`, `compare`.
- **Analyzers**: `sql_analyzer`, `xss_analyzer`, `cmd_analyzer`, `path_traversal_analyzer`.
- **Advanced**: `ja4`, `ja4h`, `dlp_violation`, `schema_violation`.

See [Match Kinds Reference](references/match-kinds.md) for full details on each type.

## Best Practices

1. **Performance**: Use structural filters (`method`, `uri`) before expensive analyzers or regexes.
2. **Safety**: Always run `node scripts/validate_rules.cjs` before deploying new rules.
3. **JA4/JA4H**: Use these for robust client fingerprinting rather than relying solely on User-Agent.
4. **DLP**: Rules using `dlp_violation` are evaluated in a deferred pass; ensure they are tagged correctly if manually editing JSON.

## Workflow

1. **Research**: Define the threat model (e.g., "blocking admin access from non-JA4-verified clients").
2. **Draft**: Create the JSON/YAML rule using the [Rule Examples](references/rule-examples.md).
3. **Verify**: Run `node scripts/validate_rules.cjs <file>` to check for schema errors.
4. **Test**: Run `cargo test` in `apps/synapse-pingora` and use the procedural simulator to verify behavior.

## Resources

- [Match Kinds Reference](references/match-kinds.md): Exhaustive list of all supported match types and options.
- [Rule Examples](references/rule-examples.md): Templates for common security policies (SQLi, XSS, SSRF, Access Control).
