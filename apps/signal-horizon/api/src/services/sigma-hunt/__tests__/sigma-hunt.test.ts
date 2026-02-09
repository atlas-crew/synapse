import { describe, it, expect, vi } from 'vitest';
import type { RedisKv } from '../../../storage/redis/kv.js';
import type { ClickHouseService } from '../../../storage/clickhouse/index.js';
import { SigmaHuntService, extractAndValidateSigmaWhereClause } from '../index.js';

function createMemoryKv(): RedisKv {
  const kv = new Map<string, string>();
  const sets = new Map<string, Set<string>>();

  return {
    get: async (key) => kv.get(key) ?? null,
    set: async (key, value) => {
      kv.set(key, value);
      return true;
    },
    del: async (key) => {
      const existed = kv.delete(key);
      sets.delete(key);
      return existed ? 1 : 0;
    },
    incr: async (key) => {
      const next = (parseInt(kv.get(key) ?? '0', 10) || 0) + 1;
      kv.set(key, String(next));
      return next;
    },
    incrby: async (key, amount) => {
      const next = (parseInt(kv.get(key) ?? '0', 10) || 0) + amount;
      kv.set(key, String(next));
      return next;
    },
    mget: async (keys) => keys.map((k) => kv.get(k) ?? null),
    sadd: async (key, ...members) => {
      const set = sets.get(key) ?? new Set<string>();
      let added = 0;
      for (const m of members) {
        if (!set.has(m)) {
          set.add(m);
          added += 1;
        }
      }
      sets.set(key, set);
      return added;
    },
    srem: async (key, ...members) => {
      const set = sets.get(key);
      if (!set) return 0;
      let removed = 0;
      for (const m of members) {
        if (set.delete(m)) removed += 1;
      }
      return removed;
    },
    smembers: async (key) => Array.from(sets.get(key) ?? []),
  };
}

const SIGMA_SQL = `-- Suspicious cURL User Agent
SELECT * FROM signal_events
WHERE JSONExtractString(metadata, 'user_agent') ILIKE 'curl/%'
ORDER BY timestamp DESC LIMIT 1000`;

describe('extractAndValidateSigmaWhereClause', () => {
  it('extracts WHERE clause from expected template', () => {
    const where = extractAndValidateSigmaWhereClause(SIGMA_SQL);
    expect(where).toContain("JSONExtractString(metadata, 'user_agent')");
    expect(where).toContain("ILIKE 'curl/%'");
  });

  it('rejects templates not matching expected shape', () => {
    expect(() => extractAndValidateSigmaWhereClause('SELECT 1')).toThrow();
  });
});

describe('SigmaHuntService', () => {
  it('creates, lists, updates, and deletes rules', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });
    const rules1 = await svc.listRules('tenant-1');
    expect(rules1).toHaveLength(1);
    expect(rules1[0]?.id).toBe(rule.id);

    const updated = await svc.updateRule('tenant-1', rule.id, { enabled: false });
    expect(updated?.enabled).toBe(false);

    const deleted = await svc.deleteRule('tenant-1', rule.id);
    expect(deleted).toBe(true);
    const rules2 = await svc.listRules('tenant-1');
    expect(rules2).toHaveLength(0);
  });

  it('runs scheduled hunts and upserts leads', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValue([
        {
          timestamp: '2025-01-01 00:00:00.000',
          sensor_id: 'sensor-1',
          request_id: 'req_1',
          signal_type: 'IP_THREAT',
          source_ip: '203.0.113.10',
          anon_fingerprint: 'a'.repeat(64),
          severity: 'HIGH',
          confidence: 1.0,
        },
        {
          timestamp: '2025-01-01 00:01:00.000',
          sensor_id: 'sensor-1',
          request_id: 'req_1',
          signal_type: 'IP_THREAT',
          source_ip: '203.0.113.10',
          anon_fingerprint: 'a'.repeat(64),
          severity: 'HIGH',
          confidence: 1.0,
        },
      ]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });

    const result = await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    expect(result.tenants).toBe(1);
    expect(result.rules).toBe(1);
    expect(result.matches).toBe(2);
    expect(result.leadsUpserted).toBe(1);

    const leads = await svc.listLeads('tenant-1', 200);
    expect(leads).toHaveLength(1);
    expect(leads[0]?.matchCount).toBe(2);
    expect(leads[0]?.pivot.requestId).toBe('req_1');
  });
});

