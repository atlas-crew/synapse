import type { WafConfig } from 'synapse-api';
import { parseConfigValue } from './config.js';
import { pretty, formatStatus, formatTable } from './format.js';
import { UsageError, defaultIO, type IO, type Parsed, type SynapseClientLike } from './types.js';

export async function runCommand(
  client: SynapseClientLike,
  parsed: Parsed,
  io: IO = defaultIO
): Promise<void> {
  const { command, args, globals } = parsed;
  const output = (data: unknown) => {
    if (globals.json) {
      pretty(io, data);
    } else if (typeof data === 'object' && data !== null) {
      pretty(io, data);
    } else {
      io.log(String(data));
    }
  };

  switch (command) {
    case 'health': {
      const result = await client.health();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(`Status: ${result.status}`);
        io.log(`Service: ${result.service}`);
        if (result.uptime) io.log(`Uptime: ${result.uptime}s`);
        if (result.version) io.log(`Version: ${result.version}`);
      }
      break;
    }

    case 'status': {
      const result = await client.getStatus();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(formatStatus(result as unknown as Record<string, unknown>));
      }
      break;
    }

    case 'metrics': {
      const result = await client.getMetrics();
      io.log(result);
      break;
    }

    case 'entities': {
      const result = await client.listEntities();
      if (globals.json) {
        pretty(io, result);
      } else {
        if (result.entities.length === 0) {
          io.log('No entities tracked');
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
          io.log(formatTable(rows));
        }
      }
      break;
    }

    case 'blocks': {
      const result = await client.listBlocks();
      if (globals.json) {
        pretty(io, result);
      } else {
        if (result.blocks.length === 0) {
          io.log('No blocks recorded');
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
          io.log(formatTable(rows));
        }
      }
      break;
    }

    case 'release': {
      if (args.length < 1) throw new UsageError('release requires entityId or IP address');
      const result = await client.releaseEntity(args[0]);
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(result.released ? `Released: ${args[0]}` : `Not found: ${args[0]}`);
      }
      break;
    }

    case 'release-all': {
      const result = await client.releaseAll();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(`Released ${result.released} entities`);
      }
      break;
    }

    case 'config': {
      const result = await client.getConfig();
      output(result);
      break;
    }

    case 'config-set': {
      if (args.length < 1) throw new UsageError('config-set requires key=value arguments');
      const updates: Record<string, unknown> = {};
      for (const arg of args) {
        const [key, ...rest] = arg.split('=');
        const value = rest.join('=');
        if (!key || value === undefined) {
          throw new UsageError(`Invalid config format: ${arg} (expected key=value)`);
        }
        updates[key] = parseConfigValue(value);
      }
      const result = await client.updateConfig(updates as Partial<WafConfig>);
      output(result);
      break;
    }

    case 'rules': {
      const result = await client.listRules();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(
          `Total: ${result.stats.total} | Blocking: ${result.stats.blocking} | Runtime: ${result.stats.runtime}`
        );
        if (result.rules.length > 0) {
          io.log('');
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
          io.log(formatTable(rows));
          if (result.rules.length > 20) io.log(`... and ${result.rules.length - 20} more`);
        }
      }
      break;
    }

    case 'rule-add': {
      if (args.length < 1) throw new UsageError('rule-add requires JSON rule definition');
      let rule: any;
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
      if (args.length < 1) throw new UsageError('rule-remove requires rule ID');
      const ruleId = parseInt(args[0], 10);
      if (isNaN(ruleId)) throw new UsageError('rule-remove requires a numeric rule ID');
      const result = await client.removeRule(ruleId);
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(result.removed ? `Removed rule ${ruleId}` : `Rule ${ruleId} not found`);
      }
      break;
    }

    case 'rules-clear': {
      const result = await client.clearRules();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(`Cleared ${result.cleared} runtime rules`);
      }
      break;
    }

    case 'reload': {
      const result = await client.reloadRules();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(result.message);
        io.log(`Total rules: ${result.stats.total}`);
      }
      break;
    }

    case 'evaluate': {
      if (args.length < 2) throw new UsageError('evaluate requires method and URL arguments');
      const request: any = { method: args[0].toUpperCase(), url: args[1] };
      if (args[2]) {
        try {
          request.headers = JSON.parse(args[2]);
        } catch {
          throw new UsageError('Invalid JSON for headers');
        }
      }
      const result = await client.evaluate(request);
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(`Matched: ${result.matched}`);
        io.log(`Total Risk: ${result.totalRisk}`);
        io.log(`Would Block: ${result.wouldBlock}`);
        if (result.blockReason) io.log(`Block Reason: ${result.blockReason}`);
        if (result.matchedRules.length > 0) {
          io.log('\nMatched Rules:');
          for (const r of result.matchedRules) {
            io.log(`  - [${r.id}] ${r.name || 'unnamed'} (risk: ${r.risk})`);
          }
        }
      }
      break;
    }

    case 'actors': {
      const result = await client.listActors();
      if (globals.json) {
        pretty(io, result);
      } else {
        io.log(`Total actors: ${result.count}`);
        if (result.actors.length > 0) {
          io.log('');
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
          io.log(formatTable(rows));
          if (result.actors.length > 20) io.log(`... and ${result.actors.length - 20} more`);
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
      if (args.length < 2) throw new UsageError('actor-fingerprint requires IP and fingerprint');
      const result = await client.setActorFingerprint(args[0], args[1]);
      output(result);
      break;
    }

    default:
      throw new UsageError(`Unknown command: ${command}`);
  }
}

