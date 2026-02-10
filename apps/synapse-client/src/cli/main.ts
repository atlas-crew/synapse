import { helpText } from './help.js';
import { parseArgv } from './parse.js';
import { runCommand } from './commands.js';
import { UsageError, VERSION, defaultIO, type IO, type ClientFactory, type Parsed } from './types.js';

export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv,
  makeClient: ClientFactory,
  io: IO = defaultIO
): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parseArgv(argv, env);
  } catch (err) {
    if (err instanceof UsageError) {
      io.error(`Usage error: ${err.message}`);
      io.error('Run "synapse --help" for usage information');
      return 1;
    }
    io.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  if (parsed.version) {
    io.log(VERSION);
    return 0;
  }

  if (parsed.help || !parsed.command) {
    io.log(helpText());
    return parsed.help ? 0 : 1;
  }

  if (!parsed.globals.url) {
    io.error('Error: --url or SYNAPSE_URL is required');
    io.error('Run "synapse --help" for usage information');
    return 1;
  }

  const client = makeClient({
    baseUrl: parsed.globals.url,
    debug: parsed.globals.debug,
    timeout: parsed.globals.timeout,
  });

  try {
    await runCommand(client, parsed, io);
    return 0;
  } catch (err) {
    if (err instanceof UsageError) {
      io.error(`Usage error: ${err.message}`);
      io.error('Run "synapse --help" for usage information');
      return 1;
    }
    io.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

