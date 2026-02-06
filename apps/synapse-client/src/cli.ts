#!/usr/bin/env node
/**
 * Synapse CLI
 * Command-line interface for the Synapse (risk-server) API
 */

import { SynapseClient } from 'synapse-api';
import type { EvaluateRequest, RuleDefinition } from 'synapse-api';

const VERSION = '0.1.0';

// ============================================================================
// Types
// ============================================================================

class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

interface GlobalOpts {
  url: string;
  json: boolean;
  debug: boolean;
  timeout: number;
}

interface Parsed {
  command?: string;
  args: string[];
  globals: GlobalOpts;
  help?: boolean;
  version?: boolean;
}

// ============================================================================
// Argument Parsing
// ============================================================================

function parseArgv(argv: string[]): Parsed {
  const globals: GlobalOpts = {
    url: process.env.SYNAPSE_URL || '',
    json: !!process.env.SYNAPSE_JSON,
    debug: !!process.env.SYNAPSE_DEBUG,
    timeout: parseInt(process.env.SYNAPSE_TIMEOUT || '30000', 10),
  };

  const outArgs: string[] = [];
  let command: string | undefined;
  let help = false;
  let version = false;

  const it = argv[Symbol.iterator]();
  let cur = it.next();

  while (!cur.done) {
    const a = cur.value;

    // Stop parsing options after --
    if (a === '--') {
      cur = it.next();
      while (!cur.done) {
        outArgs.push(cur.value);
        cur = it.next();
      }
      break;
    }

    // Help/Version flags
    if (a === '--help' || a === '-h') {
      help = true;
      cur = it.next();
      continue;
    }
    if (a === '--version' || a === '-v') {
      version = true;
      cur = it.next();
      continue;
    }

    // Global options
    if (a === '--json') {
      globals.json = true;
      cur = it.next();
      continue;
    }
    if (a === '--debug' || a === '-d') {
      globals.debug = true;
      cur = it.next();
      continue;
    }
    if (a === '--url' || a === '-u') {
      cur = it.next();
      if (cur.done || !cur.value) throw new UsageError('--url requires a value');
      globals.url = cur.value;
      cur = it.next();
      continue;
    }
    if (a === '--timeout' || a === '-t') {
      cur = it.next();
      if (cur.done || !cur.value) throw new UsageError('--timeout requires a value');
      globals.timeout = parseInt(cur.value, 10);
      if (isNaN(globals.timeout)) throw new UsageError('--timeout must be a number');
      cur = it.next();
      continue;
    }

    // First non-flag argument is the command
    if (!command && !a.startsWith('-')) {
      command = a;
      cur = it.next();
      continue;
    }

    // Remaining arguments
    outArgs.push(a);
    cur = it.next();
  }

  return { command, args: outArgs, globals, help, version };
}

// ============================================================================
// Output Formatting
// ============================================================================

function pretty(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

function formatTable(rows: string[][]): string {
  if (rows.length === 0) return '';
  const cols = rows[0].length;
  const widths: number[] = Array(cols).fill(0);

  for (const row of rows) {
    for (let i = 0; i < row.length; i++) {
      widths[i] = Math.max(widths[i], row[i].length);
    }
  }

  return rows
    .map((row) => row.map((cell, i) => cell.padEnd(widths[i])).join('  '))
    .join('\n');
}

function formatStatus(status: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(status)) {
    const displayKey = key.replace(/([A-Z])/g, ' $1').toLowerCase();
    lines.push(`${displayKey}: ${value}`);
  }
  return lines.join('\n');
}

// ============================================================================
// Command Handlers
// ============================================================================

async function runCommand(client: SynapseClient, parsed: Parsed): Promise<void> {
  const { command, args, globals } = parsed;
  const output = (data: unknown) => {
    if (globals.json) {
      pretty(data);
    } else if (typeof data === 'object' && data !== null) {
      pretty(data); // Default to JSON for objects
    } else {
      console.log(data);
    }
  };

  switch (command) {
    // === Health & Status ===
    case 'health': {
      const result = await client.health();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Status: ${result.status}`);
        console.log(`Service: ${result.service}`);
        if (result.uptime) console.log(`Uptime: ${result.uptime}s`);
        if (result.version) console.log(`Version: ${result.version}`);
      }
      break;
    }

    case 'status': {
      const result = await client.getStatus();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(formatStatus(result as unknown as Record<string, unknown>));
      }
      break;
    }

    case 'metrics': {
      const result = await client.getMetrics();
      console.log(result);
      break;
    }

    // === Entity Management ===
    case 'entities': {
      const result = await client.listEntities();
      if (globals.json) {
        pretty(result);
      } else {
        if (result.entities.length === 0) {
          console.log('No entities tracked');
        } else {
          const rows = [
            ['ID', 'IP', 'Risk', 'Requests', 'Blocked', 'Last Seen'],
            ...result.entities.map((e) => [
              e.id.slice(0, 8),
              e.ip || '-',
              String(e.risk),
              String(e.requestCount),
              e.blocked ? 'Yes' : 'No',
              new Date(e.lastSeen).toLocaleString(),
            ]),
          ];
          console.log(formatTable(rows));
        }
      }
      break;
    }

    case 'blocks': {
      const result = await client.listBlocks();
      if (globals.json) {
        pretty(result);
      } else {
        if (result.blocks.length === 0) {
          console.log('No blocks recorded');
        } else {
          const rows = [
            ['Entity', 'IP', 'Mode', 'Reason', 'Blocked At'],
            ...result.blocks.map((b) => [
              b.entityId.slice(0, 8),
              b.ip,
              b.mode,
              b.reason.slice(0, 30),
              new Date(b.blockedAt).toLocaleString(),
            ]),
          ];
          console.log(formatTable(rows));
        }
      }
      break;
    }

    case 'release': {
      if (args.length < 1) {
        throw new UsageError('release requires entityId or IP address');
      }
      const result = await client.releaseEntity(args[0]);
      if (globals.json) {
        pretty(result);
      } else {
        console.log(result.released ? `Released: ${args[0]}` : `Not found: ${args[0]}`);
      }
      break;
    }

    case 'release-all': {
      const result = await client.releaseAll();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Released ${result.released} entities`);
      }
      break;
    }

    // === Configuration ===
    case 'config': {
      const result = await client.getConfig();
      output(result);
      break;
    }

    case 'config-set': {
      if (args.length < 1) {
        throw new UsageError('config-set requires key=value arguments');
      }
      const updates: Record<string, unknown> = {};
      for (const arg of args) {
        const [key, ...rest] = arg.split('=');
        const value = rest.join('=');
        if (!key || value === undefined) {
          throw new UsageError(`Invalid config format: ${arg} (expected key=value)`);
        }
        // Parse value
        if (value === 'true') updates[key] = true;
        else if (value === 'false') updates[key] = false;
        else if (!isNaN(Number(value))) updates[key] = Number(value);
        else updates[key] = value;
      }
      const result = await client.updateConfig(updates);
      output(result);
      break;
    }

    // === WAF Rules ===
    case 'rules': {
      const result = await client.listRules();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Total: ${result.stats.total} | Blocking: ${result.stats.blocking} | Runtime: ${result.stats.runtime}`);
        if (result.rules.length > 0) {
          console.log('');
          const rows = [
            ['ID', 'Name', 'Risk', 'Blocking', 'Classification'],
            ...result.rules.slice(0, 20).map((r) => [
              String(r.id),
              (r.name || '-').slice(0, 30),
              String(r.risk ?? 0),
              r.blocking ? 'Yes' : 'No',
              r.classification || '-',
            ]),
          ];
          console.log(formatTable(rows));
          if (result.rules.length > 20) {
            console.log(`... and ${result.rules.length - 20} more`);
          }
        }
      }
      break;
    }

    case 'rule-add': {
      if (args.length < 1) {
        throw new UsageError('rule-add requires JSON rule definition');
      }
      let rule: RuleDefinition;
      try {
        rule = JSON.parse(args[0]);
      } catch {
        throw new UsageError('Invalid JSON for rule definition');
      }
      const ttl = args[1] ? parseInt(args[1], 10) : undefined;
      const result = await client.addRule(rule, ttl);
      output(result);
      break;
    }

    case 'rule-remove': {
      if (args.length < 1) {
        throw new UsageError('rule-remove requires rule ID');
      }
      const ruleId = parseInt(args[0], 10);
      if (isNaN(ruleId)) {
        throw new UsageError('rule-remove requires a numeric rule ID');
      }
      const result = await client.removeRule(ruleId);
      if (globals.json) {
        pretty(result);
      } else {
        console.log(result.removed ? `Removed rule ${ruleId}` : `Rule ${ruleId} not found`);
      }
      break;
    }

    case 'rules-clear': {
      const result = await client.clearRules();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Cleared ${result.cleared} runtime rules`);
      }
      break;
    }

    case 'reload': {
      const result = await client.reloadRules();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(result.message);
        console.log(`Total rules: ${result.stats.total}`);
      }
      break;
    }

    case 'evaluate': {
      if (args.length < 2) {
        throw new UsageError('evaluate requires method and URL arguments');
      }
      const request: EvaluateRequest = {
        method: args[0].toUpperCase(),
        url: args[1],
      };
      // Optional headers as JSON
      if (args[2]) {
        try {
          request.headers = JSON.parse(args[2]);
        } catch {
          throw new UsageError('Invalid JSON for headers');
        }
      }
      const result = await client.evaluate(request);
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Matched: ${result.matched}`);
        console.log(`Total Risk: ${result.totalRisk}`);
        console.log(`Would Block: ${result.wouldBlock}`);
        if (result.blockReason) console.log(`Block Reason: ${result.blockReason}`);
        if (result.matchedRules.length > 0) {
          console.log('\nMatched Rules:');
          for (const r of result.matchedRules) {
            console.log(`  - [${r.id}] ${r.name || 'unnamed'} (risk: ${r.risk})`);
          }
        }
      }
      break;
    }

    // === Actor Tracking ===
    case 'actors': {
      const result = await client.listActors();
      if (globals.json) {
        pretty(result);
      } else {
        console.log(`Total actors: ${result.count}`);
        if (result.actors.length > 0) {
          console.log('');
          const rows = [
            ['IP', 'Risk', 'Sessions', 'JS', 'Suspicious', 'Last Activity'],
            ...result.actors.slice(0, 20).map((a) => [
              a.ip,
              String(a.risk),
              String(a.sessionCount),
              a.jsExecuted ? 'Yes' : 'No',
              a.suspicious ? 'Yes' : 'No',
              new Date(a.lastActivity).toLocaleString(),
            ]),
          ];
          console.log(formatTable(rows));
          if (result.actors.length > 20) {
            console.log(`... and ${result.actors.length - 20} more`);
          }
        }
      }
      break;
    }

    case 'actor-stats': {
      const result = await client.getActorStats();
      output(result);
      break;
    }

    case 'actor-fingerprint': {
      if (args.length < 2) {
        throw new UsageError('actor-fingerprint requires IP and fingerprint');
      }
      const result = await client.setActorFingerprint(args[0], args[1]);
      output(result);
      break;
    }

    default:
      throw new UsageError(`Unknown command: ${command}`);
  }
}

// ============================================================================
// Help
// ============================================================================

function printHelp(): void {
  console.log(`
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
  synapse --url http://localhost:3000 evaluate GET "/api/users?id=1"

ENVIRONMENT:
  SYNAPSE_URL           Server URL (required if not using --url)
  SYNAPSE_JSON=1        Enable JSON output
  SYNAPSE_DEBUG=1       Enable debug logging
  SYNAPSE_TIMEOUT       Request timeout in milliseconds
`);
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  const parsed = parseArgv(process.argv.slice(2));

  if (parsed.version) {
    console.log(VERSION);
    process.exit(0);
  }

  if (parsed.help || !parsed.command) {
    printHelp();
    process.exit(parsed.help ? 0 : 1);
  }

  if (!parsed.globals.url) {
    console.error('Error: --url or SYNAPSE_URL is required');
    console.error('Run "synapse --help" for usage information');
    process.exit(1);
  }

  const client = new SynapseClient({
    baseUrl: parsed.globals.url,
    debug: parsed.globals.debug,
    timeout: parsed.globals.timeout,
  });

  try {
    await runCommand(client, parsed);
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(`Usage error: ${err.message}`);
      console.error('Run "synapse --help" for usage information');
      process.exit(1);
    }
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}

main();
