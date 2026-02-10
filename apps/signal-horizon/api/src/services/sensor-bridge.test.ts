import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Logger } from 'pino';
import { SensorBridge } from './sensor-bridge.js';

const wsMock = vi.hoisted(() => {
  let lastArgs: unknown[] = [];
  let lastInstance: InstanceType<typeof MockWebSocket> | null = null;

  class MockWebSocket {
    static OPEN = 1;
    readyState = 0;
    on = vi.fn();
    send = vi.fn();
    close = vi.fn();
  }

  const ctor = vi.fn(function (this: MockWebSocket, ...args: unknown[]) {
    lastArgs = args;
    const inst = new MockWebSocket();
    lastInstance = inst;
    return inst;
  }) as unknown as { new (...args: unknown[]): MockWebSocket; OPEN: number };

  ctor.OPEN = MockWebSocket.OPEN;

  return {
    ctor,
    getLastArgs: () => lastArgs,
    getInstance: () => lastInstance,
    reset: () => {
      lastArgs = [];
      lastInstance = null;
      ctor.mockClear();
    },
  };
});

vi.mock('ws', () => ({
  default: wsMock.ctor,
}));

const createLogger = (): Logger => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger);

/** Type for the mocked WebSocket instance returned by wsMock.getInstance() */
type WsInstance = {
  on: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  readyState: number;
};

/** Helper: get the mocked WS instance's event handler by name */
function getHandler<T extends (...args: any[]) => void>(inst: WsInstance, event: string): T {
  const match = inst.on.mock.calls.find(([ev]: [string]) => ev === event);
  if (!match) throw new Error(`No handler registered for event "${event}"`);
  return match[1] as T;
}

describe('SensorBridge', () => {
  beforeEach(() => {
    wsMock.reset();
  });

  it('passes API key as Authorization header during WS upgrade', async () => {
    const bridge = new SensorBridge({
      hubWsUrl: 'ws://localhost:3100/ws/sensors',
      pingoraAdminUrl: 'http://localhost:6191',
      apiKey: 'bridge-api-key',
      sensorId: 'synapse-pingora-1',
      sensorName: 'Synapse Pingora',
    }, createLogger());

    await bridge.start();

    expect(wsMock.ctor).toHaveBeenCalledTimes(1);
    const lastArgs = wsMock.getLastArgs();
    // Hub supports auth via either headers or token query param; current behavior uses `?token=`.
    expect(lastArgs[0]).toBe('ws://localhost:3100/ws/sensors?token=bridge-api-key');
    expect(lastArgs[1]).toMatchObject({
      headers: {
        Authorization: 'Bearer bridge-api-key',
      },
    });
  });

  it('closes WebSocket with 4003 on auth-failed message', async () => {
    const logger = createLogger();
    const bridge = new SensorBridge({
      hubWsUrl: 'ws://localhost:3100/ws/sensors',
      pingoraAdminUrl: 'http://localhost:6191',
      apiKey: 'bridge-api-key',
      sensorId: 'synapse-pingora-1',
      sensorName: 'Synapse Pingora',
    }, logger);

    await bridge.start();

    const wsInstance = wsMock.getInstance() as WsInstance;
    const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');

    messageHandler(Buffer.from(JSON.stringify({ type: 'auth-failed', error: 'Invalid API key' })));

    expect(wsInstance.close).toHaveBeenCalledWith(4003, 'Auth failed');
    expect(logger.error).toHaveBeenCalledWith(
      { error: 'Invalid API key' },
      'Authentication failed'
    );
  });

  it('does not start heartbeat after auth-failed', async () => {
    const logger = createLogger();
    const bridge = new SensorBridge({
      hubWsUrl: 'ws://localhost:3100/ws/sensors',
      pingoraAdminUrl: 'http://localhost:6191',
      apiKey: 'bridge-api-key',
      sensorId: 'synapse-pingora-1',
      sensorName: 'Synapse Pingora',
    }, logger);

    await bridge.start();

    const wsInstance = wsMock.getInstance() as WsInstance;
    const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');

    messageHandler(Buffer.from(JSON.stringify({ type: 'auth-failed', error: 'Invalid API key' })));

    // After auth-failed, isAuthenticated should remain false -> isConnected() returns false
    expect(bridge.isConnected()).toBe(false);

    // No heartbeat should have been sent (ws.send not called with heartbeat payload)
    const sendCalls = wsInstance.send.mock.calls as [string][];
    const heartbeats = sendCalls.filter((call) => {
      try {
        const parsed = JSON.parse(call[0]);
        return parsed.type === 'heartbeat';
      } catch {
        return false;
      }
    });
    expect(heartbeats).toHaveLength(0);
  });

  it('logs status on unexpected response', async () => {
    const logger = createLogger();
    const bridge = new SensorBridge({
      hubWsUrl: 'ws://localhost:3100/ws/sensors',
      pingoraAdminUrl: 'http://localhost:6191',
      apiKey: 'bridge-api-key',
      sensorId: 'synapse-pingora-1',
      sensorName: 'Synapse Pingora',
    }, logger);

    await bridge.start();

    const wsInstance = wsMock.getInstance() as WsInstance;
    const handler = getHandler<(req: unknown, res: { statusCode?: number; statusMessage?: string; headers?: Record<string, string> }) => void>(wsInstance, 'unexpected-response');

    handler({}, { statusCode: 401, statusMessage: 'Unauthorized', headers: { foo: 'bar' } });

    expect(logger.error).toHaveBeenCalledWith(
      {
        statusCode: 401,
        statusMessage: 'Unauthorized',
        headers: { foo: 'bar' },
      },
      'WebSocket upgrade rejected'
    );
  });

  describe('stop()', () => {
    it('clears heartbeat interval and reconnect timeout', async () => {
      vi.useFakeTimers();
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        heartbeatIntervalMs: 5000,
        reconnectDelayMs: 1000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1; // OPEN

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));

      const clearIntervalSpy = vi.spyOn(global, 'clearInterval');

      await bridge.stop();

      // clearInterval should have been called for the heartbeat interval
      expect(clearIntervalSpy).toHaveBeenCalled();

      // WebSocket should have been closed
      expect(wsInstance.close).toHaveBeenCalledWith(1000, 'Bridge shutting down');

      // After stop, bridge should report disconnected
      expect(bridge.isConnected()).toBe(false);

      clearIntervalSpy.mockRestore();
      vi.useRealTimers();
    });

    it('is idempotent — calling stop twice does not throw', async () => {
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
      }, createLogger());

      await bridge.start();
      await bridge.stop();
      // Second stop should be safe — ws is already null, intervals already cleared
      await expect(bridge.stop()).resolves.toBeUndefined();
    });
  });

  describe('sendHeartbeat()', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
      vi.useRealTimers();
    });

    it('computes RPS delta from previous stats', async () => {
      vi.useFakeTimers({ now: 1000000 });

      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: { status: 'running', uptime_secs: 100, version: '1.0.0' },
            }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: {
                requests_total: 1000, requests_blocked: 10,
                bytes_in: 0, bytes_out: 0, active_connections: 5,
                avg_latency_ms: 2, uptime_secs: 100,
              },
            }),
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        heartbeatIntervalMs: 30000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1;

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');

      // Auth success triggers first heartbeat (which sets lastStats with requests_total=1000)
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));
      // Wait for the async sendHeartbeat to complete
      await vi.advanceTimersByTimeAsync(0);

      // First heartbeat should have requestsLastMinute = 0 (no previous stats)
      const firstSendCalls = wsInstance.send.mock.calls as [string][];
      const firstHeartbeat = firstSendCalls
        .map((c) => { try { return JSON.parse(c[0]); } catch { return null; } })
        .find((m) => m?.type === 'heartbeat');
      expect(firstHeartbeat?.payload.requestsLastMinute).toBe(0);

      // Now update stats to simulate more requests and advance time by 30s
      fetchMock.mockImplementation(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: { status: 'running', uptime_secs: 130, version: '1.0.0' },
            }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: {
                requests_total: 1500, requests_blocked: 15,
                bytes_in: 0, bytes_out: 0, active_connections: 5,
                avg_latency_ms: 2, uptime_secs: 130,
              },
            }),
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });

      // Advance 30s to trigger the next heartbeat from setInterval
      await vi.advanceTimersByTimeAsync(30000);

      const allSendCalls = wsInstance.send.mock.calls as [string][];
      const heartbeats = allSendCalls
        .map((c) => { try { return JSON.parse(c[0]); } catch { return null; } })
        .filter((m) => m?.type === 'heartbeat');

      // The second heartbeat should have a nonzero requestsLastMinute
      // Delta: 1500-1000=500 requests in 30000ms -> (500/30000)*60000 = 1000 rpm
      expect(heartbeats.length).toBeGreaterThanOrEqual(2);
      expect(heartbeats[heartbeats.length - 1].payload.requestsLastMinute).toBeGreaterThan(0);

      await bridge.stop();
    });

    it('handles no previous stats gracefully — first heartbeat has 0 requestsLastMinute', async () => {
      vi.useFakeTimers({ now: 1000000 });

      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: { status: 'running', uptime_secs: 10, version: '1.0.0' },
            }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: {
                requests_total: 500, requests_blocked: 5,
                bytes_in: 0, bytes_out: 0, active_connections: 2,
                avg_latency_ms: 1, uptime_secs: 10,
              },
            }),
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        heartbeatIntervalMs: 30000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1;

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));
      await vi.advanceTimersByTimeAsync(0);

      const sendCalls = wsInstance.send.mock.calls as [string][];
      const heartbeat = sendCalls
        .map((c) => { try { return JSON.parse(c[0]); } catch { return null; } })
        .find((m) => m?.type === 'heartbeat');

      expect(heartbeat?.payload.requestsLastMinute).toBe(0);

      await bridge.stop();
    });
  });

  describe('scheduleReconnect()', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('schedules reconnect after WebSocket close event', async () => {
      vi.useFakeTimers();
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        reconnectDelayMs: 2000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      const closeHandler = getHandler<(code: number, reason: Buffer) => void>(wsInstance, 'close');

      wsMock.ctor.mockClear();

      // Fire close event
      closeHandler(1006, Buffer.from('abnormal'));

      // Before delay: no reconnect yet
      expect(wsMock.ctor).toHaveBeenCalledTimes(0);

      // Advance past reconnect delay
      await vi.advanceTimersByTimeAsync(2000);

      // After delay: WebSocket constructor called again for reconnect
      expect(wsMock.ctor).toHaveBeenCalledTimes(1);

      await bridge.stop();
    });

    it('does not reconnect if already shutting down', async () => {
      vi.useFakeTimers();
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        reconnectDelayMs: 1000,
      }, createLogger());

      await bridge.start();

      // Stop the bridge first (sets isShuttingDown = true)
      await bridge.stop();

      wsMock.ctor.mockClear();

      // Advance well past reconnect delay — no reconnect should happen
      await vi.advanceTimersByTimeAsync(5000);
      expect(wsMock.ctor).toHaveBeenCalledTimes(0);
    });
  });

  describe('isConnected()', () => {
    it('returns true when WebSocket is OPEN and authenticated', async () => {
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1; // OPEN

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));

      expect(bridge.isConnected()).toBe(true);
    });

    it('returns false when WebSocket is not OPEN', async () => {
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;

      // readyState defaults to 0 (CONNECTING), not OPEN
      expect(bridge.isConnected()).toBe(false);

      // Set to CLOSING (2)
      wsInstance.readyState = 2;
      expect(bridge.isConnected()).toBe(false);
    });

    it('returns false before authentication even if WebSocket is OPEN', async () => {
      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1; // OPEN but not yet authenticated

      expect(bridge.isConnected()).toBe(false);
    });
  });

  describe('buildHeartbeat()', () => {
    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
      vi.useRealTimers();
    });

    it('reports unhealthy when health data is null', async () => {
      vi.useFakeTimers({ now: 2000000 });

      // Return null health (fetch fails), valid stats
      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return { ok: false, status: 503 } as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: {
                requests_total: 100, requests_blocked: 1,
                bytes_in: 0, bytes_out: 0, active_connections: 1,
                avg_latency_ms: 1, uptime_secs: 10,
              },
            }),
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        heartbeatIntervalMs: 60000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1;

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));
      await vi.advanceTimersByTimeAsync(0);

      const sendCalls = wsInstance.send.mock.calls as [string][];
      const heartbeat = sendCalls
        .map((c) => { try { return JSON.parse(c[0]); } catch { return null; } })
        .find((m) => m?.type === 'heartbeat');

      expect(heartbeat?.payload.status).toBe('unhealthy');
      expect(heartbeat?.payload.configHash).toBe('cfg-unknown');

      await bridge.stop();
    });

    it('reports degraded when health status is not running', async () => {
      vi.useFakeTimers({ now: 3000000 });

      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true,
            json: async () => ({
              success: true,
              data: { status: 'starting', uptime_secs: 1, version: '1.0.0' },
            }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return { ok: false, status: 503 } as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const bridge = new SensorBridge({
        hubWsUrl: 'ws://localhost:3100/ws/sensors',
        pingoraAdminUrl: 'http://localhost:6191',
        apiKey: 'bridge-api-key',
        sensorId: 'synapse-pingora-1',
        sensorName: 'Synapse Pingora',
        heartbeatIntervalMs: 60000,
      }, createLogger());

      await bridge.start();

      const wsInstance = wsMock.getInstance() as WsInstance;
      wsInstance.readyState = 1;

      const messageHandler = getHandler<(data: Buffer) => void>(wsInstance, 'message');
      messageHandler(Buffer.from(JSON.stringify({ type: 'auth-success', sensorId: 's1', tenantId: 't1' })));
      await vi.advanceTimersByTimeAsync(0);

      const sendCalls = wsInstance.send.mock.calls as [string][];
      const heartbeat = sendCalls
        .map((c) => { try { return JSON.parse(c[0]); } catch { return null; } })
        .find((m) => m?.type === 'heartbeat');

      expect(heartbeat?.payload.status).toBe('degraded');
      expect(heartbeat?.payload.configHash).toBe('cfg-1.0.0');

      await bridge.stop();
    });
  });
});
