#!/usr/bin/env node
/**
 * CLI entrypoint.
 * Most logic lives in cli-lib.ts for testability.
 */

import { SynapseClient } from 'synapse-api';
import { main } from './cli-lib.js';

const exitCode = await main(
  process.argv.slice(2),
  process.env,
  (opts) => new SynapseClient(opts)
);

process.exit(exitCode);
