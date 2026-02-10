import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Logger } from 'pino';
import { SensorBridge } from './sensor-bridge.js';

const wsMock = vi.hoisted(() => {
  let lastArgs: unknown[] = [];

  class MockWebSocket {
    static OPEN = 1;
    readyState = 0;
    on = vi.fn();
    send = vi.fn();
    close = vi.fn();
  }

  const ctor = vi.fn((...args: unknown[]) => {
    lastArgs = args;
    return new MockWebSocket();
  }) as unknown as { new (...args: unknown[]): MockWebSocket; OPEN: number };

  ctor.OPEN = MockWebSocket.OPEN;

  return {
    ctor,
    getLastArgs: () => lastArgs,
    reset: () => {
      lastArgs = [];
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

    const wsInstance = wsMock.ctor.mock.results[0]?.value as {
      on: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
      send: ReturnType<typeof vi.fn>;
      readyState: number;
    };

    const onCalls = wsInstance.on.mock.calls;
    const messageHandler = onCalls.find(([event]: [string]) => event === 'message')?.[1] as
      ((data: Buffer) => void) | undefined;

    expect(messageHandler).toBeTypeOf('function');
    messageHandler!(Buffer.from(JSON.stringify({ type: 'auth-failed', error: 'Invalid API key' })));

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

    const wsInstance = wsMock.ctor.mock.results[0]?.value as {
      on: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
      send: ReturnType<typeof vi.fn>;
      readyState: number;
    };

    const onCalls = wsInstance.on.mock.calls;
    const messageHandler = onCalls.find(([event]: [string]) => event === 'message')?.[1] as
      ((data: Buffer) => void) | undefined;

    expect(messageHandler).toBeTypeOf('function');
    messageHandler!(Buffer.from(JSON.stringify({ type: 'auth-failed', error: 'Invalid API key' })));

    // After auth-failed, isAuthenticated should remain false → isConnected() returns false
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

    const wsInstance = wsMock.ctor.mock.results[0]?.value as { on: (event: string, cb: (...args: any[]) => void) => void };
    const onCalls = (wsInstance.on as ReturnType<typeof vi.fn>).mock.calls;
    const handler = onCalls.find(([event]) => event === 'unexpected-response')?.[1] as
      ((req: unknown, res: { statusCode?: number; statusMessage?: string; headers?: Record<string, string> }) => void) | undefined;

    expect(handler).toBeTypeOf('function');
    handler?.({}, { statusCode: 401, statusMessage: 'Unauthorized', headers: { foo: 'bar' } });

    expect(logger.error).toHaveBeenCalledWith(
      {
        statusCode: 401,
        statusMessage: 'Unauthorized',
        headers: { foo: 'bar' },
      },
      'WebSocket upgrade rejected'
    );
  });
});
