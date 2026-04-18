/**
 * Synapse WAF rule catalog sync (CLI).
 *
 * Usage:
 *   pnpm -C apps/signal-horizon/api run rules:sync
 *   pnpm -C apps/signal-horizon/api run rules:sync -- --source=/path/to/production_rules.json
 *   pnpm -C apps/signal-horizon/api run rules:sync -- --catalog-version=v2026.04 --no-prune
 *
 * Env:
 *   SYNAPSE_PRODUCTION_RULES_PATH  Overrides the default source path.
 *   LOG_LEVEL                      Pino log level (default: info).
 */

import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';
import pino from 'pino';
import {
  readSynapseRulesFile,
  syncSynapseRules,
  type SyncOptions,
} from '../src/services/synapse-rule-loader.js';

const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' });

interface CliArgs {
  source: string;
  catalogVersion?: string;
  prune: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const defaultSource =
    process.env.SYNAPSE_PRODUCTION_RULES_PATH ?? defaultSourcePath();

  let source = defaultSource;
  let catalogVersion: string | undefined;
  let prune = true;

  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--source=')) source = arg.slice('--source='.length);
    else if (arg.startsWith('--catalog-version='))
      catalogVersion = arg.slice('--catalog-version='.length);
    else if (arg === '--no-prune') prune = false;
    else if (arg === '--prune') prune = true;
    else logger.warn({ arg }, 'Ignoring unrecognized argument');
  }

  return { source, catalogVersion, prune };
}

function defaultSourcePath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // apps/signal-horizon/api/prisma → apps/synapse-pingora/src/production_rules.json
  return path.resolve(here, '../../../synapse-pingora/src/production_rules.json');
}

async function main() {
  const args = parseArgs(process.argv);
  logger.info({ source: args.source, prune: args.prune }, 'Loading Synapse rule catalog');

  const records = await readSynapseRulesFile(args.source);
  logger.info({ count: records.length }, 'Parsed rule records');

  const prisma = new PrismaClient();
  try {
    const options: SyncOptions = {
      catalogVersion: args.catalogVersion,
      prune: args.prune,
    };
    const result = await syncSynapseRules(prisma, records, options, logger);
    logger.info(
      {
        catalogHash: result.catalogHash,
        catalogVersion: result.catalogVersion,
        inserted: result.inserted,
        updated: result.updated,
        deleted: result.deleted,
        skipped: result.skipped,
        warnings: result.warnings.length,
      },
      'Sync complete'
    );
    if (result.warnings.length > 0) {
      for (const w of result.warnings) logger.warn(w);
    }
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  logger.error({ err }, 'Sync failed');
  process.exit(1);
});
