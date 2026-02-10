import { VERSION } from './types.js';

export function helpText(): string {
  return `
Synapse CLI v${VERSION}
TypeScript client for the Synapse (risk-server) API

USAGE:
  synapse [options] <command> [arguments]

GLOBAL OPTIONS:
  -u, --url <url>       Synapse server URL [env: SYNAPSE_URL] (required)
      --json            Output as JSON [env: SYNAPSE_JSON=1]
  -d, --debug           Enable debug logging [env: SYNAPSE_DEBUG=1]
  -t, --timeout <ms>    Request timeout in ms [env: SYNAPSE_TIMEOUT] (default: 30000)
  -h, --help            Show this help message
  -v, --version         Show version

COMMANDS:
  Health & Status:
    health              Check server health
    status              Get sensor status and metrics
    metrics             Get Prometheus-formatted metrics

  Entity Management:
    entities            List all tracked entities
    blocks              List all block records
    release <id|ip>     Release a blocked entity
    release-all         Release all blocked entities

  Configuration:
    config              Get system configuration
    config-set <k=v>... Update configuration (e.g., autoblockThreshold=80)

  WAF Rules:
    rules               List all WAF rules
    rule-add <json> [ttl]  Add a runtime rule (optional TTL in seconds)
    rule-remove <id>    Remove a runtime rule
    rules-clear         Clear all runtime rules
    reload              Reload rules from file
    evaluate <method> <url> [headers-json]  Evaluate request against rules

  Actor Tracking:
    actors              List all tracked actors
    actor-stats         Get actor tracking statistics
    actor-fingerprint <ip> <fp>  Set actor fingerprint

EXAMPLES:
  synapse --url http://localhost:3000 status
  synapse --url http://localhost:3000 --json entities
  synapse --url http://localhost:3000 release 192.168.1.100
  synapse --url http://localhost:3000 config-set autoblockThreshold=80
  synapse --url http://localhost:3000 config-set trustedProxyCidrs='[\"10.0.0.0/8\"]'
  synapse --url http://localhost:3000 evaluate GET \"/api/users?id=1\"

ENVIRONMENT:
  SYNAPSE_URL           Server URL (required if not using --url)
  SYNAPSE_JSON=1        Enable JSON output
  SYNAPSE_DEBUG=1       Enable debug logging
  SYNAPSE_TIMEOUT       Request timeout in milliseconds
`;
}

