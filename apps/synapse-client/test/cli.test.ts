import { describe, it, expect, vi } from 'vitest';
import { main, VERSION, type IO, type ClientFactory } from '../src/cli-lib.js';

function captureIO(): { io: IO; stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: {
      log: (msg = '') => stdout.push(String(msg)),
      error: (msg = '') => stderr.push(String(msg)),
    },
    stdout,
    stderr,
  };
}

function makeOkClient() {
  return {
    health: vi.fn(async () => ({ status: 'ok', service: 'risk-server', uptime: 12, version: '1.2.3' })),
    getStatus: vi.fn(async () => ({
      totalRequests: 1,
      blockedRequests: 2,
      requestRate: 3,
      blockRate: 4,
      fallbackRate: 5,
      rulesCount: 6,
      autoblockThreshold: 7,
      riskDecayPerMinute: 8,
      riskBasedBlockingEnabled: true,
      requestBlockingEnabled: true,
      allowIpSpoofing: false,
      mode: 'demo',
    })),
    getMetrics: vi.fn(async () => 'm'),
    listEntities: vi.fn(async () => ({ entities: [], count: 0 })),
    listBlocks: vi.fn(async () => ({ blocks: [], count: 0 })),
    releaseEntity: vi.fn(async () => ({ released: true })),
    releaseAll: vi.fn(async () => ({ released: 9 })),
    getConfig: vi.fn(async () => ({ config: { port: 3000 } as any })),
    updateConfig: vi.fn(async () => ({ config: { requestBlockingEnabled: true } as any, updated: ['x'] })),
    listRules: vi.fn(async () => ({
      rules: [{ id: 1, description: 'd', matches: [], blocking: true, risk: 10, name: 'n', classification: 'c' }],
      stats: { total: 1, blocking: 1, riskBased: 1, runtime: 0 },
    })),
    addRule: vi.fn(async () => ({ success: true, rule: { id: 1, description: 'd', matches: [] } as any, stats: { total: 1, blocking: 0, riskBased: 1, runtime: 1 } })),
    removeRule: vi.fn(async () => ({ removed: true, stats: { total: 1, blocking: 0, riskBased: 1, runtime: 0 } })),
    clearRules: vi.fn(async () => ({ cleared: 2, stats: { total: 1, blocking: 0, riskBased: 1, runtime: 0 } })),
    reloadRules: vi.fn(async () => ({ success: true, message: 'reloaded', stats: { total: 3, blocking: 1, riskBased: 2 } })),
    evaluate: vi.fn(async () => ({
      matched: true,
      totalRisk: 42,
      wouldBlock: true,
      blockReason: 'b',
      matchedRules: [{ id: 1, risk: 42, blocking: true, reasons: ['r'], name: 'n' }],
    })),
    listActors: vi.fn(async () => ({ actors: [], count: 0 })),
    getActorStats: vi.fn(async () => ({ totalActors: 1, suspiciousActors: 0, jsExecutedCount: 1, fingerprintChanges: 0, averageSessionCount: 1 })),
    setActorFingerprint: vi.fn(async () => ({ success: true, actor: { ip: '1.2.3.4' } as any })),
  };
}

describe('synapse-client CLI (cli-lib)', () => {
  it('prints version', async () => {
    const { io, stdout } = captureIO();
    const code = await main(['--version'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n').trim()).toBe(VERSION);
  });

  it('prints help', async () => {
    const { io, stdout } = captureIO();
    const code = await main(['--help'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Synapse CLI');
    expect(stdout.join('\n')).toContain('USAGE:');
    expect(stdout.join('\n')).toContain('COMMANDS:');
  });

  it('requires --url or SYNAPSE_URL', async () => {
    const { io, stderr } = captureIO();
    const code = await main(['status'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('--url or SYNAPSE_URL is required');
  });

  it('runs health (human)', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'health'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Status: ok');
    expect(client.health).toHaveBeenCalledTimes(1);
  });

  it('runs status', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'status'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('total requests: 1');
    expect(client.getStatus).toHaveBeenCalledTimes(1);
  });

  it('runs metrics', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'metrics'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('m');
    expect(client.getMetrics).toHaveBeenCalledTimes(1);
  });

  it('runs entities (empty)', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'entities'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('No entities tracked');
    expect(client.listEntities).toHaveBeenCalledTimes(1);
  });

  it('runs blocks (empty)', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'blocks'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('No blocks recorded');
    expect(client.listBlocks).toHaveBeenCalledTimes(1);
  });

  it('release requires id/ip', async () => {
    const { io, stderr } = captureIO();
    const code = await main(['--url', 'http://x', 'release'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('release requires entityId or IP address');
  });

  it('runs release', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'release', '1.2.3.4'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Released: 1.2.3.4');
    expect(client.releaseEntity).toHaveBeenCalledWith('1.2.3.4');
  });

  it('runs release-all', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'release-all'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Released 9 entities');
    expect(client.releaseAll).toHaveBeenCalledTimes(1);
  });

  it('runs config (default json for objects)', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'config'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('"config"');
    expect(client.getConfig).toHaveBeenCalledTimes(1);
  });

  it('config-set parses booleans/numbers/null/json/quoted', async () => {
    const client = makeOkClient();
    const { io } = captureIO();
    const code = await main(
      [
        '--url',
        'http://x',
        'config-set',
        'riskBasedBlockingEnabled=false',
        'autoblockThreshold=80',
        'trustedProxyCidrs=["10.0.0.0/8"]',
        'maxIpsTracked=null',
        'targetOrigin="http://example.com:8080"',
      ],
      {},
      (() => client) as unknown as ClientFactory,
      io
    );
    expect(code).toBe(0);
    expect(client.updateConfig).toHaveBeenCalledWith({
      riskBasedBlockingEnabled: false,
      autoblockThreshold: 80,
      trustedProxyCidrs: ['10.0.0.0/8'],
      maxIpsTracked: null,
      targetOrigin: 'http://example.com:8080',
    } as any);
  });

  it('runs rules', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'rules'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Total: 1');
    expect(client.listRules).toHaveBeenCalledTimes(1);
  });

  it('rule-add requires json', async () => {
    const { io, stderr } = captureIO();
    const code = await main(['--url', 'http://x', 'rule-add', 'not-json'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('Invalid JSON for rule definition');
  });

  it('runs rule-add with ttl', async () => {
    const client = makeOkClient();
    const { io } = captureIO();
    const code = await main(
      ['--url', 'http://x', 'rule-add', '{"description":"d","matches":[]}', '60'],
      {},
      (() => client) as unknown as ClientFactory,
      io
    );
    expect(code).toBe(0);
    expect(client.addRule).toHaveBeenCalledWith({ description: 'd', matches: [] }, 60);
  });

  it('rule-remove requires numeric id', async () => {
    const { io, stderr } = captureIO();
    const code = await main(['--url', 'http://x', 'rule-remove', 'abc'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('numeric rule ID');
  });

  it('runs rule-remove', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'rule-remove', '1'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Removed rule 1');
    expect(client.removeRule).toHaveBeenCalledWith(1);
  });

  it('runs rules-clear', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'rules-clear'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Cleared 2 runtime rules');
    expect(client.clearRules).toHaveBeenCalledTimes(1);
  });

  it('runs reload', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'reload'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('reloaded');
    expect(stdout.join('\n')).toContain('Total rules: 3');
    expect(client.reloadRules).toHaveBeenCalledTimes(1);
  });

  it('evaluate validates headers json', async () => {
    const { io, stderr } = captureIO();
    const code = await main(
      ['--url', 'http://x', 'evaluate', 'GET', '/x', '{not-json}'],
      {},
      (() => makeOkClient()) as unknown as ClientFactory,
      io
    );
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('Invalid JSON for headers');
  });

  it('runs evaluate', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'evaluate', 'GET', '/x'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Would Block: true');
    expect(client.evaluate).toHaveBeenCalledWith({ method: 'GET', url: '/x' });
  });

  it('runs actors', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'actors'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('Total actors: 0');
    expect(client.listActors).toHaveBeenCalledTimes(1);
  });

  it('runs actor-stats', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(['--url', 'http://x', 'actor-stats'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('"totalActors"');
    expect(client.getActorStats).toHaveBeenCalledTimes(1);
  });

  it('runs actor-fingerprint', async () => {
    const client = makeOkClient();
    const { io, stdout } = captureIO();
    const code = await main(
      ['--url', 'http://x', 'actor-fingerprint', '1.2.3.4', 'fp'],
      {},
      (() => client) as unknown as ClientFactory,
      io
    );
    expect(code).toBe(0);
    expect(stdout.join('\n')).toContain('"success"');
    expect(client.setActorFingerprint).toHaveBeenCalledWith('1.2.3.4', 'fp');
  });

  it('unknown command is usage error', async () => {
    const { io, stderr } = captureIO();
    const code = await main(['--url', 'http://x', 'nope'], {}, (() => makeOkClient()) as unknown as ClientFactory, io);
    expect(code).toBe(1);
    expect(stderr.join('\n')).toContain('Unknown command');
  });

  it('runtime error returns exit 2', async () => {
    const client = makeOkClient();
    client.health.mockRejectedValueOnce(new Error('boom'));
    const { io, stderr } = captureIO();
    const code = await main(['--url', 'http://x', 'health'], {}, (() => client) as unknown as ClientFactory, io);
    expect(code).toBe(2);
    expect(stderr.join('\n')).toContain('boom');
  });
});
