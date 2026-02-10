/**
 * Synapse CLI library (public surface for tests + entrypoint).
 *
 * Implementation is split across src/cli/* to keep files <500 LOC.
 */

export { VERSION } from './cli/types.js';
export { UsageError } from './cli/types.js';
export { defaultIO } from './cli/types.js';

export type { IO } from './cli/types.js';
export type { GlobalOpts } from './cli/types.js';
export type { Parsed } from './cli/types.js';
export type { SynapseClientLike } from './cli/types.js';
export type { ClientFactory } from './cli/types.js';

export { parseArgv } from './cli/parse.js';
export { runCommand } from './cli/commands.js';
export { helpText } from './cli/help.js';
export { main } from './cli/main.js';

