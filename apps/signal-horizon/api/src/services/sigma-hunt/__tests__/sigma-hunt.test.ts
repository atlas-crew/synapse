import { describe, it, expect, vi } from 'vitest';
import type { RedisKv } from '../../../storage/redis/kv.js';
import type { ClickHouseService } from '../../../storage/clickhouse/index.js';
import { buildRedisKey } from '../../../storage/redis/keys.js';
import { SigmaHuntService, SigmaValidationError, extractAndValidateSigmaWhereClause } from '../index.js';

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

  it('rejects comment-only templates (empty after stripping)', () => {
    const sql = `-- comment\n-- another\n\n`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(SigmaValidationError);
  });

  it('rejects oversized templates (> 50k)', () => {
    expect(() => extractAndValidateSigmaWhereClause('x'.repeat(50_001))).toThrow(SigmaValidationError);
  });

  it('rejects oversized WHERE clause (> 20k)', () => {
    const hugeWhere = 'x'.repeat(20_001);
    const sql = `SELECT * FROM signal_events WHERE ${hugeWhere} ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(SigmaValidationError);
  });

  it('allows WHERE clause at exactly 20k chars', () => {
    const hugeWhere = 'x'.repeat(20_000);
    const sql = `SELECT * FROM signal_events WHERE ${hugeWhere} ORDER BY timestamp DESC LIMIT 1000`;
    expect(extractAndValidateSigmaWhereClause(sql)).toBe(hugeWhere);
  });

  it('rejects SQL line comments (--) in WHERE clause', () => {
    const sql = `SELECT * FROM signal_events WHERE 1=1 -- AND tenant_id = 'evil' ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects SQL block comments (/* */) in WHERE clause', () => {
    const sql = `SELECT * FROM signal_events WHERE 1=1 /* sneaky */ ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects semicolons', () => {
    const sql = `SELECT * FROM signal_events WHERE 1=1; ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects UNION outside a single-quoted string even with escaped quotes inside the string', () => {
    const sql = `SELECT * FROM signal_events WHERE x = 'it''s fine' UNION SELECT 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects unbalanced single quotes in WHERE clause', () => {
    const sql = `SELECT * FROM signal_events WHERE x = 'unterminated ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/unbalanced/i);
  });

  it('rejects backslash-escaped quotes that break out of a string literal', () => {
    const sql = `SELECT * FROM signal_events WHERE JSONExtractString(metadata, 'x') = 'safe\\' UNION SELECT 1 --' ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(SigmaValidationError);
  });

  it('rejects additional backslash-based quote patterns', () => {
    const cases = [
      `SELECT * FROM signal_events WHERE x = 'a\\\\' UNION SELECT 1 ORDER BY timestamp DESC LIMIT 1000`,
      `SELECT * FROM signal_events WHERE x = 'a\\'' UNION SELECT 1 ORDER BY timestamp DESC LIMIT 1000`,
      `SELECT * FROM signal_events WHERE x = 'a\\\\\\'' UNION SELECT 1 ORDER BY timestamp DESC LIMIT 1000`,
    ];
    for (const sql of cases) {
      expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(SigmaValidationError);
    }
  });

  it('rejects null bytes and other control characters', () => {
    const sql = `SELECT * FROM signal_events WHERE 1=1\u0000 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/control/i);
  });

  it('rejects forbidden keywords outside string literals', () => {
    const cases: Array<{ name: string; where: string; re?: RegExp }> = [
      { name: 'FORMAT', where: '1=1 FORMAT JSON' },
      { name: 'INTO OUTFILE', where: "1=1 INTO OUTFILE 'x'" },
      { name: 'SELECT', where: '1=1 SELECT 1' },
      { name: 'INSERT', where: '1=1 INSERT 1' },
      { name: 'UPDATE', where: '1=1 UPDATE 1' },
      { name: 'DELETE', where: '1=1 DELETE 1' },
      { name: 'DROP', where: '1=1 DROP 1' },
      { name: 'ALTER', where: '1=1 ALTER 1' },
      { name: 'CREATE', where: '1=1 CREATE 1' },
      { name: 'ATTACH', where: '1=1 ATTACH 1' },
      { name: 'DETACH', where: '1=1 DETACH 1' },
      { name: 'SYSTEM', where: '1=1 SYSTEM 1' },
      { name: 'EXPLAIN', where: '1=1 EXPLAIN 1' },
      { name: 'SHOW', where: '1=1 SHOW TABLES' },
      { name: 'SET', where: '1=1 SET max_execution_time = 1' },
      { name: 'DESCRIBE', where: '1=1 DESCRIBE signal_events' },
      { name: 'TRUNCATE', where: '1=1 TRUNCATE 1' },
      { name: 'RENAME', where: '1=1 RENAME 1' },
      { name: 'GRANT', where: '1=1 GRANT 1' },
      { name: 'REVOKE', where: '1=1 REVOKE 1' },
      { name: 'KILL', where: '1=1 KILL 1' },
      { name: 'OPTIMIZE', where: '1=1 OPTIMIZE 1' },
      { name: 'EXCHANGE', where: '1=1 EXCHANGE 1' },
    ];

    for (const c of cases) {
      const sql = `SELECT * FROM signal_events WHERE ${c.where} ORDER BY timestamp DESC LIMIT 1000`;
      expect(() => extractAndValidateSigmaWhereClause(sql), c.name).toThrow(/forbidden fragment/i);
    }
  });

  it('rejects forbidden keywords when adjacent to parentheses', () => {
    const sql1 = `SELECT * FROM signal_events WHERE (UNION SELECT 1) ORDER BY timestamp DESC LIMIT 1000`;
    const sql2 = `SELECT * FROM signal_events WHERE (SELECT 1) ORDER BY timestamp DESC LIMIT 1000`;
    const sql3 = `SELECT * FROM signal_events WHERE x IN (SELECT 1) ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql1)).toThrow(/forbidden fragment/i);
    expect(() => extractAndValidateSigmaWhereClause(sql2)).toThrow(/forbidden fragment/i);
    expect(() => extractAndValidateSigmaWhereClause(sql3)).toThrow(/forbidden fragment/i);
  });

  it('rejects UNION even with tab/newline separators', () => {
    const sql = `SELECT * FROM signal_events WHERE 1=1\tUNION\nSELECT 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects ClickHouse external data source table functions', () => {
    const funcs = [
      'cluster',
      'clusterallreplicas',
      'url',
      'file',
      's3',
      'hdfs',
      'jdbc',
      'mysql',
      'postgresql',
      'input',
      'odbc',
      'remoteSecure',
      'dictionary',
      'merge',
    ];

    for (const fn of funcs) {
      const sql = `SELECT * FROM signal_events WHERE ${fn}('x') = 1 ORDER BY timestamp DESC LIMIT 1000`;
      expect(() => extractAndValidateSigmaWhereClause(sql), fn).toThrow(new RegExp(`${fn}\\(`, 'i'));
    }
  });

  it('rejects ClickHouse external data source calls regardless of case', () => {
    const cases = ['REMOTE', 'Remote', 'CLUSTER', 'ClusterAllReplicas', 'S3', 'uRl'];
    for (const c of cases) {
      const sql = `SELECT * FROM signal_events WHERE ${c}('x') = 1 ORDER BY timestamp DESC LIMIT 1000`;
      expect(() => extractAndValidateSigmaWhereClause(sql), c).toThrow(/forbidden fragment/i);
    }
  });

  it('rejects ClickHouse external table functions', () => {
    const sql = `SELECT * FROM signal_events WHERE remote('host', 'db', 't') = 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/remote\(/i);
  });

  it('rejects ClickHouse external table functions with whitespace before paren', () => {
    const sql = `SELECT * FROM signal_events WHERE remote ('host', 'db', 't') = 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/remote\(/i);
  });

  it('allows forbidden keywords inside single-quoted string literals', () => {
    const sql = `SELECT * FROM signal_events WHERE JSONExtractString(metadata, 'ua') = ' UNION SELECT DROP SHOW SET EXPLAIN DESCRIBE ' ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).not.toThrow();
  });

  it('does not treat substrings as forbidden keywords (word boundary)', () => {
    const sql = `SELECT * FROM signal_events WHERE systematic = 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).not.toThrow();
  });

  it('rejects forbidden keywords immediately after closing quote (no whitespace)', () => {
    const sql = `SELECT * FROM signal_events WHERE x = 'safe'UNION SELECT 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden fragment/i);
  });

  it('rejects double-quoted identifiers containing forbidden keywords', () => {
    const sql = `SELECT * FROM signal_events WHERE "UNION" = 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow();
  });

  it('rejects backticks', () => {
    const sql = `SELECT * FROM signal_events WHERE \`x\` = 1 ORDER BY timestamp DESC LIMIT 1000`;
    expect(() => extractAndValidateSigmaWhereClause(sql)).toThrow(/forbidden character/i);
  });
});

describe('SigmaHuntService', () => {
  it('rejects invalid rule inputs (tenantId, name)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    await expect(svc.createRule('', { name: 'x', sqlTemplate: SIGMA_SQL })).rejects.toBeInstanceOf(
      SigmaValidationError
    );
    await expect(svc.createRule('tenant-1', { name: '', sqlTemplate: SIGMA_SQL })).rejects.toBeInstanceOf(
      SigmaValidationError
    );
    await expect(
      svc.createRule('tenant-1', { name: 'x'.repeat(121), sqlTemplate: SIGMA_SQL })
    ).rejects.toBeInstanceOf(SigmaValidationError);
  });

  it('rejects overly long descriptions (> 2000 chars)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    await expect(
      svc.createRule('tenant-1', { name: 'curl', description: 'x'.repeat(2001), sqlTemplate: SIGMA_SQL })
    ).rejects.toBeInstanceOf(SigmaValidationError);
  });

  it('enforces tenant isolation for rules (list/update/delete)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    const r1 = await svc.createRule('tenant-1', { name: 'r1', sqlTemplate: SIGMA_SQL });
    const r2 = await svc.createRule('tenant-2', { name: 'r2', sqlTemplate: SIGMA_SQL });

    const t1 = await svc.listRules('tenant-1');
    const t2 = await svc.listRules('tenant-2');
    expect(t1.map((r) => r.id)).toEqual([r1.id]);
    expect(t2.map((r) => r.id)).toEqual([r2.id]);

    await expect(svc.updateRule('tenant-2', r1.id, { enabled: false })).resolves.toBeNull();
    await expect(svc.deleteRule('tenant-2', r1.id)).resolves.toBe(false);
  });

  it('does not allow updating sqlTemplate/whereClause via updateRule input', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });
    const updated = await svc.updateRule('tenant-1', rule.id, {
      enabled: false,
      // @ts-expect-error: ensure unexpected props don't mutate stored rule fields.
      sqlTemplate: `SELECT * FROM signal_events WHERE 1=1 ORDER BY timestamp DESC LIMIT 1000`,
      // @ts-expect-error: ensure unexpected props don't mutate stored rule fields.
      whereClause: `1=1; DROP TABLE signal_events`,
    } as any);

    expect(updated?.sqlTemplate).toBe(rule.sqlTemplate);
    expect(updated?.whereClause).toBe(rule.whereClause);
  });

  it('rejects invalid updateRule inputs (name/description)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });
    await expect(svc.updateRule('tenant-1', rule.id, { name: '' })).rejects.toBeInstanceOf(SigmaValidationError);
    await expect(
      svc.updateRule('tenant-1', rule.id, { name: 'x'.repeat(121) })
    ).rejects.toBeInstanceOf(SigmaValidationError);
    await expect(
      svc.updateRule('tenant-1', rule.id, { description: 'x'.repeat(2001) })
    ).rejects.toBeInstanceOf(SigmaValidationError);
  });

  it('runScheduledHunts skips disabled rules (no ClickHouse query)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValue([]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });
    await svc.updateRule('tenant-1', rule.id, { enabled: false });

    const res = await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    expect(res.rules).toBe(0);
    expect(vi.mocked(clickhouse.queryWithParams!)).not.toHaveBeenCalled();
  });

  it('createRule persists enabled=false and scheduler skips it', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValue([]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL, enabled: false });
    expect(rule.enabled).toBe(false);

    const res = await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    expect(res.rules).toBe(0);
    expect(vi.mocked(clickhouse.queryWithParams!)).not.toHaveBeenCalled();
  });

  it('updateRule allows clearing description with empty string', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
    const svc = new SigmaHuntService(kv, logger, null);

    const rule = await svc.createRule('tenant-1', { name: 'curl', description: 'desc', sqlTemplate: SIGMA_SQL });
    const updated = await svc.updateRule('tenant-1', rule.id, { description: '' });
    expect(updated?.description).toBe('');
  });

  it('deleteRule deletes the cursor key', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValue([]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    const rule = await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });
    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });

    const cursorKey = buildRedisKey({
      namespace: 'sigma-hunt',
      version: 1,
      tenantId: 'tenant-1',
      dataType: 'rule-cursor',
      id: rule.id,
    });

    expect(await kv.get(cursorKey)).toBeTruthy();
    await expect(svc.deleteRule('tenant-1', rule.id)).resolves.toBe(true);
    expect(await kv.get(cursorKey)).toBeNull();
  });

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

    // Ensure query uses ClickHouse params for tenant/time/limit (no interpolation).
    const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
    const sql = String(call[0]);
    const normSql = sql.replace(/\s+/g, ' ');
    expect(sql).toContain('tenant_id = {tenantId:String}');
    expect(sql).toContain('toDateTime64({startTime:String}, 3)');
    expect(sql).toContain('toDateTime64({endTime:String}, 3)');
    expect(sql).toContain("JSONExtractString(metadata, 'user_agent')");
    expect(sql).toContain("ILIKE 'curl/%'");
    expect(sql).toMatch(/AND\s*\(\s*JSONExtractString/);
    expect(normSql).toContain(
      `AND (JSONExtractString(metadata, 'user_agent') ILIKE 'curl/%') ORDER BY timestamp DESC`
    );
    expect(sql).toContain('LIMIT {limit:UInt32}');
    expect(sql).not.toContain('tenant-1');
  });

  it('computeLeadId is stable across runs for identical rows (increments matchCount)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const row = {
      timestamp: '2025-01-01 00:00:00.000',
      sensor_id: 'sensor-1',
      request_id: 'req_1',
      signal_type: 'IP_THREAT',
      source_ip: '203.0.113.10',
      anon_fingerprint: 'a'.repeat(64),
      severity: 'HIGH',
      confidence: 1.0,
    };

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValueOnce([row]).mockResolvedValueOnce([row]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const leads = await svc.listLeads('tenant-1', 200);
    expect(leads).toHaveLength(1);
    expect(leads[0]!.matchCount).toBe(2);
  });

  it('deduplicates leads by pivot priority (requestId > anonFingerprint > sourceIp:signalType)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const rows: any[] = [
      {
        timestamp: '2025-01-01 00:00:00.000',
        sensor_id: 'sensor-1',
        request_id: 'req_same',
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.10',
        anon_fingerprint: 'a'.repeat(64),
        severity: 'HIGH',
        confidence: 1.0,
      },
      {
        timestamp: '2025-01-01 00:01:00.000',
        sensor_id: 'sensor-1',
        request_id: 'req_same',
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.99', // different IP, should still dedup by requestId
        anon_fingerprint: 'b'.repeat(64),
        severity: 'HIGH',
        confidence: 1.0,
      },
      {
        timestamp: '2025-01-01 00:00:00.000',
        sensor_id: 'sensor-1',
        request_id: null,
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.10',
        anon_fingerprint: 'f'.repeat(64),
        severity: 'HIGH',
        confidence: 1.0,
      },
      {
        timestamp: '2025-01-01 00:01:00.000',
        sensor_id: 'sensor-1',
        request_id: null,
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.99',
        anon_fingerprint: 'f'.repeat(64), // same fp, should dedup
        severity: 'HIGH',
        confidence: 1.0,
      },
      {
        timestamp: '2025-01-01 00:00:00.000',
        sensor_id: 'sensor-1',
        request_id: null,
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.10',
        anon_fingerprint: '0'.repeat(64),
        severity: 'HIGH',
        confidence: 1.0,
      },
      {
        timestamp: '2025-01-01 00:01:00.000',
        sensor_id: 'sensor-1',
        request_id: null,
        signal_type: 'IP_THREAT',
        source_ip: '203.0.113.99',
        anon_fingerprint: '0'.repeat(64), // should NOT dedup via fp; should fall back to sourceIp
        severity: 'HIGH',
        confidence: 1.0,
      },
    ];

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValue(rows),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 'r1', sqlTemplate: SIGMA_SQL });

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const leads = await svc.listLeads('tenant-1', 200);
    // requestId dedup => 1 lead (matchCount 2)
    // anonFingerprint dedup => 1 lead (matchCount 2)
    // zero-fp fallback => 2 leads (matchCount 1 each)
    expect(leads).toHaveLength(4);

    const reqLead = leads.find((l) => l.pivot.requestId === 'req_same');
    expect(reqLead?.matchCount).toBe(2);

    const fpLead = leads.find((l) => l.pivot.requestId === null && l.pivot.anonFingerprint === 'f'.repeat(64));
    expect(fpLead?.matchCount).toBe(2);

    const ipLeads = leads.filter((l) => l.pivot.requestId === null && l.pivot.anonFingerprint === null);
    expect(ipLeads.map((l) => l.pivot.sourceIp).sort()).toEqual(['203.0.113.10', '203.0.113.99']);
  });

  it('reopens ACKED leads on new matches (ACKED -> OPEN)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const row1 = {
      timestamp: '2025-01-01 00:00:00.000',
      sensor_id: 'sensor-1',
      request_id: 'req_1',
      signal_type: 'IP_THREAT',
      source_ip: '203.0.113.10',
      anon_fingerprint: 'a'.repeat(64),
      severity: 'HIGH',
      confidence: 1.0,
    };
    const row2 = {
      ...row1,
      timestamp: '2025-01-01 00:02:00.000',
    };

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockResolvedValueOnce([row1]).mockResolvedValueOnce([row2]),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const leads1 = await svc.listLeads('tenant-1', 200);
    expect(leads1).toHaveLength(1);

    const leadId = leads1[0]!.id;
    const acked = await svc.ackLead('tenant-1', leadId);
    expect(acked?.status).toBe('ACKED');
    expect(acked?.acknowledgedAt).not.toBeNull();

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const leads2 = await svc.listLeads('tenant-1', 200);
    expect(leads2).toHaveLength(1);
    expect(leads2[0]!.matchCount).toBe(2);
    expect(leads2[0]!.status).toBe('OPEN');
    expect(leads2[0]!.acknowledgedAt).toBeNull();
  });

  it('ackLead is idempotent until reopened; then sets a new acknowledgedAt', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-01T00:00:00.000Z'));
    const kv = createMemoryKv();
    const logger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
      child: vi.fn().mockReturnThis(),
    } as any;

    const row1 = {
      timestamp: '2025-01-01 00:00:00.000',
      sensor_id: 'sensor-1',
      request_id: 'req_1',
      signal_type: 'IP_THREAT',
      source_ip: '203.0.113.10',
      anon_fingerprint: 'a'.repeat(64),
      severity: 'HIGH',
      confidence: 1.0,
    };
    const row2 = {
      ...row1,
      timestamp: '2025-01-01 00:03:00.000',
    };

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi
        .fn()
        .mockResolvedValueOnce([row1]) // create lead
        .mockResolvedValueOnce([]) // no new activity
        .mockResolvedValueOnce([row2]), // reopen
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 'curl', sqlTemplate: SIGMA_SQL });

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const leadId = (await svc.listLeads('tenant-1', 200))[0]!.id;

    const ack1 = await svc.ackLead('tenant-1', leadId);
    vi.setSystemTime(new Date('2025-01-01T00:00:00.010Z'));
    const ack2 = await svc.ackLead('tenant-1', leadId);
    expect(ack1?.acknowledgedAt).toBeTruthy();
    expect(ack2?.acknowledgedAt).toBe(ack1?.acknowledgedAt);

    // No new activity: remains acked.
    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const stillAcked = (await svc.listLeads('tenant-1', 200))[0]!;
    expect(stillAcked.status).toBe('ACKED');
    expect(stillAcked.acknowledgedAt).toBe(ack1?.acknowledgedAt);

    // New activity: reopens and clears ack timestamp.
    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });
    const reopened = (await svc.listLeads('tenant-1', 200))[0]!;
    expect(reopened.status).toBe('OPEN');
    expect(reopened.acknowledgedAt).toBeNull();

    vi.setSystemTime(new Date('2025-01-01T00:00:00.020Z'));
    const ack3 = await svc.ackLead('tenant-1', leadId);
    expect(ack3?.acknowledgedAt).toBeTruthy();
    expect(ack3?.acknowledgedAt).not.toBe(ack1?.acknowledgedAt);

    vi.useRealTimers();
  });

  it('enforces tenant isolation for leads (list/ack)', async () => {
    const kv = createMemoryKv();
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

    const rowTenant1 = {
      timestamp: '2025-01-01 00:00:00.000',
      sensor_id: 'sensor-1',
      request_id: 'req_t1',
      signal_type: 'IP_THREAT',
      source_ip: '203.0.113.10',
      anon_fingerprint: 'a'.repeat(64),
      severity: 'HIGH',
      confidence: 1.0,
    };
    const rowTenant2 = {
      timestamp: '2025-01-01 00:00:00.000',
      sensor_id: 'sensor-2',
      request_id: 'req_t2',
      signal_type: 'IP_THREAT',
      source_ip: '203.0.113.20',
      anon_fingerprint: 'b'.repeat(64),
      severity: 'HIGH',
      confidence: 1.0,
    };

    const clickhouse: Partial<ClickHouseService> = {
      isEnabled: () => true,
      queryWithParams: vi.fn().mockImplementation(async (_sql, params: any) => {
        if (params?.tenantId === 'tenant-1') return [rowTenant1] as any;
        if (params?.tenantId === 'tenant-2') return [rowTenant2] as any;
        return [];
      }),
    };

    const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
    await svc.createRule('tenant-1', { name: 't1', sqlTemplate: SIGMA_SQL });
    await svc.createRule('tenant-2', { name: 't2', sqlTemplate: SIGMA_SQL });

    await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 500 });

    const leads1 = await svc.listLeads('tenant-1', 200);
    const leads2 = await svc.listLeads('tenant-2', 200);
    expect(leads1).toHaveLength(1);
    expect(leads2).toHaveLength(1);
    expect(leads1[0]!.pivot.requestId).toBe('req_t1');
    expect(leads2[0]!.pivot.requestId).toBe('req_t2');

    const leadId = leads1[0]!.id;
    await expect(svc.ackLead('tenant-2', leadId)).resolves.toBeNull();
    const acked = await svc.ackLead('tenant-1', leadId);
    expect(acked?.status).toBe('ACKED');
  });

  describe('lookbackMinutes clamping', () => {
    it('clamps value below minimum (4 → 5)', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'clamp-min', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ lookbackMinutes: 4, maxRowsPerRule: 500 });

      // The query should use the clamped 5-minute lookback, not the provided 4.
      // We verify by inspecting the startTime param: clamped lookback means a wider window
      // (5 min + 5 min overlap = 10 min from now) vs unclamped (4 min + 5 min overlap = 9 min).
      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      const startTimeStr: string = params.startTime;
      const startTime = new Date(startTimeStr.replace(' ', 'T') + 'Z');
      const now = Date.now();
      // Default start = now - lookback. Overlap subtracts 5 more minutes.
      // With clamped 5min: start = now - 5min - 5min = now - 10min
      // With unclamped 4min: start = now - 4min - 5min = now - 9min
      // The start time should be at least ~10 minutes before now (allowing some test execution time).
      const diffMinutes = (now - startTime.getTime()) / (60 * 1000);
      expect(diffMinutes).toBeGreaterThanOrEqual(9.5); // Clamped to 5, not 4
    });

    it('clamps value above maximum (1441 → 1440)', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'clamp-max', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ lookbackMinutes: 1441, maxRowsPerRule: 500 });

      // The start time should correspond to 1440min (24h) + 5min overlap, NOT 1441min + 5min.
      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      const startTimeStr: string = params.startTime;
      const startTime = new Date(startTimeStr.replace(' ', 'T') + 'Z');
      const now = Date.now();
      const diffMinutes = (now - startTime.getTime()) / (60 * 1000);
      // Clamped to 1440 + 5 overlap = 1445 max
      expect(diffMinutes).toBeLessThanOrEqual(1446);
      // Should not exceed 1441 + 5 = 1446 (unclamped value)
      expect(diffMinutes).toBeLessThanOrEqual(1446);
    });

    it('defaults to 60 when not provided', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'default-lb', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ maxRowsPerRule: 500 });

      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      const startTimeStr: string = params.startTime;
      const startTime = new Date(startTimeStr.replace(' ', 'T') + 'Z');
      const now = Date.now();
      // Default 60min + 5min overlap = ~65 minutes before now
      const diffMinutes = (now - startTime.getTime()) / (60 * 1000);
      expect(diffMinutes).toBeGreaterThanOrEqual(64);
      expect(diffMinutes).toBeLessThanOrEqual(66);
    });
  });

  describe('maxRowsPerRule clamping', () => {
    it('clamps value below minimum (9 → 10)', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'rows-min', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 9 });

      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      expect(params.limit).toBe(10); // Clamped from 9 to minimum 10
    });

    it('clamps value above maximum (5001 → 5000)', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'rows-max', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ lookbackMinutes: 60, maxRowsPerRule: 5001 });

      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      expect(params.limit).toBe(5000); // Clamped from 5001 to maximum 5000
    });

    it('defaults to 500 when not provided', async () => {
      const kv = createMemoryKv();
      const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;

      const clickhouse: Partial<ClickHouseService> = {
        isEnabled: () => true,
        queryWithParams: vi.fn().mockResolvedValue([]),
      };

      const svc = new SigmaHuntService(kv, logger, clickhouse as ClickHouseService);
      await svc.createRule('tenant-1', { name: 'rows-default', sqlTemplate: SIGMA_SQL });

      await svc.runScheduledHunts({ lookbackMinutes: 60 });

      const call = vi.mocked(clickhouse.queryWithParams!).mock.calls[0]!;
      const params = call[1] as any;
      expect(params.limit).toBe(500); // Default value
    });
  });
});
