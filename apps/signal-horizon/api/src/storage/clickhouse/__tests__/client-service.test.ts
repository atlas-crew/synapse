import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ClickHouseService } from '../client.js';
import type {
  SignalEventRow,
  HttpTransactionRow,
  LogEntryRow,
  CampaignHistoryRow,
  BlocklistHistoryRow,
} from '../client.js';
import type { Logger } from 'pino';
import { metrics } from '../../../services/metrics.js';

const createMockLogger = (): Logger =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
  } as unknown as Logger);

const createService = (enabled: boolean) => {
  const logger = createMockLogger();
  return new ClickHouseService(
    {
      host: 'localhost',
      port: 8123,
      database: 'test',
      username: 'test',
      password: 'test',
      compression: false,
      maxOpenConnections: 1,
      maxInFlightQueries: 1,
      maxInFlightStreamQueries: 1,
      queryTimeoutSec: 30,
      queueTimeoutSec: 1,
      maxRowsLimit: 1000,
    },
    logger,
    enabled
  );
};

const createSignal = (overrides: Partial<SignalEventRow> = {}): SignalEventRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 't1',
  sensor_id: 's1',
  request_id: 'r1',
  signal_type: 'test',
  source_ip: '1.2.3.4',
  fingerprint: 'fp',
  anon_fingerprint: 'anon'.padEnd(64, '0'),
  severity: 'HIGH',
  confidence: 1,
  event_count: 1,
  metadata: '{}',
  ...overrides,
});

const createTxn = (overrides: Partial<HttpTransactionRow> = {}): HttpTransactionRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 't1',
  sensor_id: 's1',
  request_id: 'r1',
  site: 'example.com',
  method: 'GET',
  path: '/',
  status_code: 200,
  latency_ms: 10,
  waf_action: null,
  ...overrides,
});

const createLog = (overrides: Partial<LogEntryRow> = {}): LogEntryRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 't1',
  sensor_id: 's1',
  request_id: 'r1',
  log_id: 'l1',
  source: 'sensor',
  level: 'info',
  message: 'hello',
  fields: null,
  method: null,
  path: null,
  status_code: null,
  latency_ms: null,
  client_ip: null,
  rule_id: null,
  ...overrides,
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ClickHouseService (direct)', () => {
  it('query() executes raw SQL and returns rows', async () => {
    const rawCallsSpy = vi.spyOn(metrics.clickhouseRawQueriesTotal, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        json: async () => [{ ok: 1 }],
      }),
    };
    (svc as any).client = fakeClient;

    const sql1 = `SELECT 1 AS ok; /* x' OR 1=1 */`;
    const sql2 = `SELECT * FROM users WHERE name = 'x' OR 1=1;`;

    const rows1 = await svc.query<{ ok: number }>(sql1);
    const rows2 = await svc.query<{ ok: number }>(sql2);

    expect(rows1).toEqual([{ ok: 1 }]);
    expect(rows2).toEqual([{ ok: 1 }]);
    expect(rawCallsSpy).toHaveBeenCalledTimes(2);
    expect(fakeClient.query).toHaveBeenCalledWith(
      expect.objectContaining({
        query: sql1,
        format: 'JSONEachRow',
        clickhouse_settings: expect.objectContaining({
          max_execution_time: 30,
          max_result_rows: '1000',
          result_overflow_mode: 'throw',
        }),
      })
    );
    expect(fakeClient.query).toHaveBeenCalledWith(
      expect.objectContaining({
        query: sql2,
        format: 'JSONEachRow',
      })
    );
  });

  it('queryWithParams() passes query_params to the underlying client', async () => {
    const rawCallsSpy = vi.spyOn(metrics.clickhouseRawQueriesTotal, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        json: async () => [{ ok: 1 }],
      }),
    };
    (svc as any).client = fakeClient;

    const sql = 'SELECT {name:String} AS name, {age:UInt32} AS age, {tags:Array(String)} AS tags';
    const params = {
      name: `x' OR 1=1 --`,
      age: 42,
      tags: ['a', `b'); DROP TABLE t; --`],
    };
    await svc.queryWithParams(sql, params);

    expect(fakeClient.query).toHaveBeenCalledWith(
      expect.objectContaining({
        query: sql,
        query_params: params,
        clickhouse_settings: expect.objectContaining({
          max_execution_time: 30,
          max_result_rows: '1000',
          result_overflow_mode: 'throw',
        }),
      })
    );
    const call = (fakeClient.query as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as any;
    expect(String(call.query)).toContain('{name:String}');
    expect(String(call.query)).toContain('{age:UInt32}');
    expect(String(call.query)).toContain('{tags:Array(String)}');
    expect(String(call.query)).not.toContain(params.name);
    expect(String(call.query)).not.toContain(String(params.age));
    expect(String(call.query)).not.toContain(String(params.tags[1]));
    expect(rawCallsSpy).not.toHaveBeenCalled();
  });

  it('query() fails if client closes after initial guard (race hits inner check)', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn(),
    };
    (svc as any).client = fakeClient;

    (svc as any).acquireQueryPermit = vi.fn().mockImplementation(async () => {
      (svc as any).client = null;
      return () => {};
    });

    await expect(svc.query('SELECT 1')).rejects.toThrow(/not available|closed/i);
    expect(fakeClient.query).not.toHaveBeenCalled();
  });

  it('queryWithParams() fails if client closes after initial guard (race hits inner check)', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn(),
    };
    (svc as any).client = fakeClient;

    (svc as any).acquireQueryPermit = vi.fn().mockImplementation(async () => {
      (svc as any).client = null;
      return () => {};
    });

    await expect(svc.queryWithParams('SELECT {x:String}', { x: 'y' })).rejects.toThrow(
      /not available|closed/i
    );
    expect(fakeClient.query).not.toHaveBeenCalled();
  });

  it('queryStream() fails if client closes after initial guard (race hits inner check)', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn(),
    };
    (svc as any).client = fakeClient;

    (svc as any).acquireQueryPermit = vi.fn().mockImplementation(async () => {
      (svc as any).client = null;
      return () => {};
    });
    (svc as any).acquireStreamPermit = vi.fn().mockResolvedValue(() => {});

    await expect(svc.queryStream('SELECT 1', 10, async () => {})).rejects.toThrow(
      /not available|closed/i
    );
    expect(fakeClient.query).not.toHaveBeenCalled();
  });

  it('query() throws when disabled', async () => {
    const svc = createService(false);
    await expect(svc.query('SELECT 1')).rejects.toThrow(/not enabled/i);
  });

  it('queryWithParams() throws when disabled', async () => {
    const svc = createService(false);
    await expect(svc.queryWithParams('SELECT 1', {})).rejects.toThrow(/not enabled/i);
  });

  it('queryOne/queryOneWithParams return first row or null', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi
        .fn()
        .mockResolvedValueOnce({ json: async () => [] })
        .mockResolvedValueOnce({ json: async () => [{ n: 1 }, { n: 2 }] })
        .mockResolvedValueOnce({ json: async () => [] })
        .mockResolvedValueOnce({ json: async () => [{ ok: true }] }),
    };
    (svc as any).client = fakeClient;

    await expect(svc.queryOne<{ n: number }>('SELECT 1')).resolves.toBeNull();
    await expect(svc.queryOne<{ n: number }>('SELECT 1')).resolves.toEqual({ n: 1 });

    await expect(svc.queryOneWithParams<{ ok: boolean }>('SELECT 1', {})).resolves.toBeNull();
    await expect(svc.queryOneWithParams<{ ok: boolean }>('SELECT 1', {})).resolves.toEqual({
      ok: true,
    });
  });

  it('insertSignalEvents()/insertHttpTransactions()/insertLogEntries increment success/failure metrics', async () => {
    const successIncSpy = vi.spyOn(metrics.clickhouseInsertSuccess, 'inc');
    const failIncSpy = vi.spyOn(metrics.clickhouseInsertFailed, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      insert: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    await svc.insertSignalEvents([createSignal()]);
    await svc.insertHttpTransactions([createTxn()]);
    await svc.insertLogEntries([createLog()]);

    expect(successIncSpy).toHaveBeenCalledWith({ table: 'signal_events' });
    expect(successIncSpy).toHaveBeenCalledWith({ table: 'http_transactions' });
    expect(successIncSpy).toHaveBeenCalledWith({ table: 'sensor_logs' });
    expect(failIncSpy).not.toHaveBeenCalled();

    fakeClient.insert.mockRejectedValueOnce(new Error('boom'));
    await expect(svc.insertSignalEvents([createSignal({ request_id: 'r2' })])).rejects.toThrow();
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'signal_events' });
  });

  it('insert* methods are no-op on empty arrays', async () => {
    const successIncSpy = vi.spyOn(metrics.clickhouseInsertSuccess, 'inc');
    const failIncSpy = vi.spyOn(metrics.clickhouseInsertFailed, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      insert: vi.fn(),
    };
    (svc as any).client = fakeClient;

    await expect(svc.insertSignalEvents([])).resolves.toBeUndefined();
    await expect(svc.insertHttpTransactions([])).resolves.toBeUndefined();
    await expect(svc.insertLogEntries([])).resolves.toBeUndefined();
    await expect(svc.insertBlocklistEvents([] as any)).resolves.toBeUndefined();

    expect(fakeClient.insert).not.toHaveBeenCalled();
    expect(successIncSpy).not.toHaveBeenCalled();
    expect(failIncSpy).not.toHaveBeenCalled();
  });

  it('insert methods rethrow on error and increment failure metrics', async () => {
    const failIncSpy = vi.spyOn(metrics.clickhouseInsertFailed, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      insert: vi.fn(),
    };
    (svc as any).client = fakeClient;

    const campaign: CampaignHistoryRow = {
      timestamp: new Date().toISOString(),
      campaign_id: 'c1',
      tenant_id: 't1',
      request_id: 'r1',
      event_type: 'created',
      name: 'n',
      status: 'active',
      severity: 'HIGH',
      is_cross_tenant: 0,
      tenants_affected: 1,
      confidence: 1,
      metadata: '{}',
    };
    const block: BlocklistHistoryRow = {
      timestamp: new Date().toISOString(),
      tenant_id: 't1',
      request_id: 'r1',
      action: 'added',
      block_type: 'ip',
      indicator: '1.2.3.4',
      source: 'test',
      reason: 'test',
      campaign_id: 'c1',
      expires_at: null,
    };

    fakeClient.insert.mockRejectedValueOnce(new Error('boom-campaign'));
    await expect(svc.insertCampaignEvent(campaign)).rejects.toThrow(/boom-campaign/i);
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'campaign_history' });

    fakeClient.insert.mockRejectedValueOnce(new Error('boom-block-1'));
    await expect(svc.insertBlocklistEvent(block)).rejects.toThrow(/boom-block-1/i);
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'blocklist_history' });

    fakeClient.insert.mockRejectedValueOnce(new Error('boom-block-batch'));
    await expect(svc.insertBlocklistEvents([block])).rejects.toThrow(/boom-block-batch/i);
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'blocklist_history' });

    fakeClient.insert.mockRejectedValueOnce(new Error('boom-txn'));
    await expect(svc.insertHttpTransactions([createTxn()])).rejects.toThrow(/boom-txn/i);
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'http_transactions' });

    fakeClient.insert.mockRejectedValueOnce(new Error('boom-log'));
    await expect(svc.insertLogEntries([createLog()])).rejects.toThrow(/boom-log/i);
    expect(failIncSpy).toHaveBeenCalledWith({ table: 'sensor_logs' });
  });

  it('insertCampaignEvent()/insertBlocklistEvent(s) no-op when disabled', async () => {
    const svc = createService(false);

    const fakeClient = {
      insert: vi.fn(),
    };
    (svc as any).client = fakeClient;

    const campaign: CampaignHistoryRow = {
      timestamp: new Date().toISOString(),
      campaign_id: 'c1',
      tenant_id: 't1',
      request_id: 'r1',
      event_type: 'created',
      name: 'n',
      status: 'active',
      severity: 'HIGH',
      is_cross_tenant: 0,
      tenants_affected: 1,
      confidence: 1,
      metadata: '{}',
    };
    const block: BlocklistHistoryRow = {
      timestamp: new Date().toISOString(),
      tenant_id: 't1',
      request_id: 'r1',
      action: 'added',
      block_type: 'ip',
      indicator: '1.2.3.4',
      source: 'test',
      reason: 'test',
      campaign_id: 'c1',
      expires_at: null,
    };

    await expect(svc.insertCampaignEvent(campaign)).resolves.toBeUndefined();
    await expect(svc.insertBlocklistEvent(block)).resolves.toBeUndefined();
    await expect(svc.insertBlocklistEvents([block])).resolves.toBeUndefined();

    expect(fakeClient.insert).not.toHaveBeenCalled();
  });

  it('insertCampaignEvent()/insertBlocklistEvent()/insertBlocklistEvents() call client and emit metrics', async () => {
    const successIncSpy = vi.spyOn(metrics.clickhouseInsertSuccess, 'inc');
    const failIncSpy = vi.spyOn(metrics.clickhouseInsertFailed, 'inc');

    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      insert: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    const campaign: CampaignHistoryRow = {
      timestamp: new Date().toISOString(),
      campaign_id: 'c1',
      tenant_id: 't1',
      request_id: 'r1',
      event_type: 'created',
      name: 'n',
      status: 'active',
      severity: 'HIGH',
      is_cross_tenant: 0,
      tenants_affected: 1,
      confidence: 1,
      metadata: '{}',
    };

    const block: BlocklistHistoryRow = {
      timestamp: new Date().toISOString(),
      tenant_id: 't1',
      request_id: 'r1',
      action: 'added',
      block_type: 'ip',
      indicator: '1.2.3.4',
      source: 'test',
      reason: 'test',
      campaign_id: 'c1',
      expires_at: null,
    };

    await svc.insertCampaignEvent(campaign);
    expect(fakeClient.insert).toHaveBeenCalledWith(
      expect.objectContaining({ table: 'campaign_history', format: 'JSONEachRow' })
    );
    expect(successIncSpy).toHaveBeenCalledWith({ table: 'campaign_history' });

    await svc.insertBlocklistEvent(block);
    expect(fakeClient.insert).toHaveBeenCalledWith(
      expect.objectContaining({ table: 'blocklist_history', format: 'JSONEachRow' })
    );

    await svc.insertBlocklistEvents([block]);
    expect(successIncSpy).toHaveBeenCalledWith({ table: 'blocklist_history' });
    expect(failIncSpy).not.toHaveBeenCalled();
  });

  it('queryStream() throws when disabled', async () => {
    const svc = createService(false);
    await expect(svc.queryStream('SELECT 1', 1, async () => {})).rejects.toThrow(/not enabled/i);
  });

  it('queryStream() throws when client is closed', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      close: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    await svc.close();
    await expect(svc.queryStream('SELECT 1', 1, async () => {})).rejects.toThrow(
      /not available|closed/i
    );
  });

  it('queryStream() passes per-query clickhouse_settings to the underlying client', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;
    (svc as any).queryLimiter = {
      acquire: vi.fn().mockResolvedValue(() => {}),
      getAvailable: () => 1,
    };
    (svc as any).streamLimiter = {
      acquire: vi.fn().mockResolvedValue(() => {}),
      getAvailable: () => 1,
    };

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        stream: async function* () {
          yield [];
        },
      }),
    };
    (svc as any).client = fakeClient;

    await svc.queryStream('SELECT 1', 100, async () => {});
    expect(fakeClient.query).toHaveBeenCalledWith(
      expect.objectContaining({
        clickhouse_settings: expect.objectContaining({
          max_execution_time: 30,
          max_result_rows: '1000',
          result_overflow_mode: 'throw',
        }),
      })
    );
  });

  it('ping() returns true on success and logs debug', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;
    const logger = (svc as any).logger as Logger;

    const fakeClient = {
      ping: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    await expect(svc.ping()).resolves.toBe(true);
    expect(logger.debug).toHaveBeenCalled();
  });

  it('ping() returns false on client error', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;
    const logger = (svc as any).logger as Logger;

    const fakeClient = {
      ping: vi.fn().mockRejectedValue(new Error('nope')),
    };
    (svc as any).client = fakeClient;

    await expect(svc.ping()).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalled();
  });

  it('ping() returns false when disabled', async () => {
    const logger = createMockLogger();
    const svc = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 1,
      } as any,
      logger,
      false
    );

    await expect(svc.ping()).resolves.toBe(false);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('query() errors are descriptive after close()', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      close: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    await svc.close();
    await expect(svc.query('SELECT 1')).rejects.toThrow(/not available|closed/i);
  });

  it('query() and queryWithParams() rethrow client errors', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      query: vi.fn().mockRejectedValue(new Error('query-fail')),
    };
    (svc as any).client = fakeClient;

    await expect(svc.query('SELECT 1')).rejects.toThrow(/query-fail/i);
    await expect(svc.queryWithParams('SELECT 1', {})).rejects.toThrow(/query-fail/i);
  });

  it('truncates SQL to 100 chars in error logs (query/queryWithParams/queryStream)', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;
    const logger = (svc as any).logger as Logger;

    (svc as any).queryLimiter = {
      acquire: vi.fn().mockResolvedValue(() => {}),
      getAvailable: () => 1,
    };
    (svc as any).streamLimiter = {
      acquire: vi.fn().mockResolvedValue(() => {}),
      getAvailable: () => 1,
    };

    const fakeClient = {
      query: vi.fn().mockRejectedValue(new Error('boom')),
    };
    (svc as any).client = fakeClient;

    const longSql = 'x'.repeat(200);

    await svc.query(longSql).catch(() => {});
    const qErrArg = (logger.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[1] === 'Query failed'
    )?.[0] as any;
    expect(String(qErrArg.sql).length).toBeLessThanOrEqual(100);

    await svc.queryWithParams(longSql, {}).catch(() => {});
    const qpErrArg = (logger.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[1] === 'Parameterized query failed'
    )?.[0] as any;
    expect(String(qpErrArg.sql).length).toBeLessThanOrEqual(100);

    await svc.queryStream(longSql, 10, async () => {}).catch(() => {});
    const qsErrArg = (logger.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[1] === 'Stream query failed'
    )?.[0] as any;
    expect(String(qsErrArg.sql).length).toBeLessThanOrEqual(100);
  });

  it('disabled mode leaves client and limiters null', () => {
    const svc = createService(false);
    expect((svc as any).client).toBeNull();
    expect((svc as any).queryLimiter).toBeNull();
    expect((svc as any).streamLimiter).toBeNull();
  });

  it('isEnabled() returns current enabled flag', () => {
    const svc = createService(false);
    expect(svc.isEnabled()).toBe(false);
    (svc as any).enabled = true;
    expect(svc.isEnabled()).toBe(true);
  });

  it('close() is a no-op when disabled', async () => {
    const svc = createService(false);
    await expect(svc.close()).resolves.toBeUndefined();
  });

  it('insertSignalEvents() is a no-op when disabled even for non-empty arrays', async () => {
    const svc = createService(false);
    const fakeClient = {
      insert: vi.fn(),
    };
    (svc as any).client = fakeClient;

    await expect(svc.insertSignalEvents([createSignal()])).resolves.toBeUndefined();
    expect(fakeClient.insert).not.toHaveBeenCalled();
  });

  it('other insert methods are no-op when disabled even for non-empty arrays', async () => {
    const svc = createService(false);
    const fakeClient = {
      insert: vi.fn(),
    };
    (svc as any).client = fakeClient;

    const block: BlocklistHistoryRow = {
      timestamp: new Date().toISOString(),
      tenant_id: 't1',
      request_id: 'r1',
      action: 'added',
      block_type: 'ip',
      indicator: '1.2.3.4',
      source: 'test',
      reason: 'test',
      campaign_id: 'c1',
      expires_at: null,
    };

    await expect(svc.insertBlocklistEvents([block])).resolves.toBeUndefined();
    await expect(svc.insertHttpTransactions([createTxn()])).resolves.toBeUndefined();
    await expect(svc.insertLogEntries([createLog()])).resolves.toBeUndefined();
    expect(fakeClient.insert).not.toHaveBeenCalled();
  });

  it('getClient() returns client or null after close()', async () => {
    const svc = createService(false);
    (svc as any).enabled = true;

    const fakeClient = {
      close: vi.fn().mockResolvedValue(undefined),
    };
    (svc as any).client = fakeClient;

    expect(svc.getClient()).toBe(fakeClient);
    await svc.close();
    expect(svc.getClient()).toBeNull();
  });
});
