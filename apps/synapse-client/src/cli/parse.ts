import { UsageError, type Parsed, type GlobalOpts } from './types.js';

export function parseArgv(argv: string[], env: NodeJS.ProcessEnv = process.env): Parsed {
  const globals: GlobalOpts = {
    url: env.SYNAPSE_URL || '',
    json: !!env.SYNAPSE_JSON,
    debug: !!env.SYNAPSE_DEBUG,
    timeout: parseInt(env.SYNAPSE_TIMEOUT || '30000', 10),
  };

  const outArgs: string[] = [];
  let command: string | undefined;
  let help = false;
  let version = false;

  const it = argv[Symbol.iterator]();
  let cur = it.next();

  while (!cur.done) {
    const a = cur.value;

    if (a === '--') {
      cur = it.next();
      while (!cur.done) {
        outArgs.push(cur.value);
        cur = it.next();
      }
      break;
    }

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

    if (!command && !a.startsWith('-')) {
      command = a;
      cur = it.next();
      continue;
    }

    outArgs.push(a);
    cur = it.next();
  }

  return { command, args: outArgs, globals, help, version };
}

