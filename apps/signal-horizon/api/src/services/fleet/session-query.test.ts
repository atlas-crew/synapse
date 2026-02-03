/**
 * FleetSessionQueryService Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { Logger } from 'pino';
import type { PrismaClient } from '@prisma/client';
import { FleetSessionQueryService } from './session-query.js';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';

class MockTunnelBroker extends EventEmitter implements Partial<TunnelBroker> {
  sendRequest = vi.fn();
  getSensorTunnelInfo = vi.fn();
}

const createLogger = (): Logger => ({
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger);

const mockPrisma = {
  sensor: {
    findMany: vi.fn(),
    findFirst: vi.fn(),
  },
} as unknown as PrismaClient;

describe('FleetSessionQueryService', () => {
  let broker: MockTunnelBroker;
  let service: FleetSessionQueryService;

  beforeEach(() => {
    broker = new MockTunnelBroker();
    service = new FleetSessionQueryService({
      prisma: mockPrisma,
      logger: createLogger(),
      tunnelBroker: broker as unknown as TunnelBroker,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('performs session search via RPC', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    
    // Setup mocks
    vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
      { id: sensorId, name: 'Sensor 1' }
    ]);
    broker.getSensorTunnelInfo.mockReturnValue({ connected: true });
    broker.sendRequest.mockResolvedValue({
      type: 'dashboard-response',
      requestId: 'req-1',
      payload: {
        status: 200,
        data: {
          sessions: [{ id: 'sess-1', riskScore: 10 }],
          totalMatches: 1
        }
      }
    });

    const result = await service.searchSessions(tenantId, { clientIp: '1.1.1.1' });

    expect(result.totalSessions).toBe(1);
    expect(result.results[0].sessions[0].id).toBe('sess-1');
    expect(broker.sendRequest).toHaveBeenCalledWith(
      sensorId,
      expect.objectContaining({
        type: 'dashboard-request',
        payload: expect.objectContaining({
          method: 'GET',
          endpoint: expect.stringContaining('/_sensor/sessions')
        })
      }),
      expect.any(Number)
    );
  });

  it('handles sensor disconnection', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    
    vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
      { id: sensorId, name: 'Sensor 1' }
    ]);
    broker.getSensorTunnelInfo.mockReturnValue({ connected: false });

    const result = await service.searchSessions(tenantId, {});

    expect(result.successfulSensors).toBe(0);
    expect(result.results[0].error).toBe('Sensor not connected');
    expect(broker.sendRequest).not.toHaveBeenCalled();
  });

  it('handles RPC errors from sensor', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    
    vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
      { id: sensorId, name: 'Sensor 1' }
    ]);
    broker.getSensorTunnelInfo.mockReturnValue({ connected: true });
    broker.sendRequest.mockResolvedValue({
      type: 'dashboard-response',
      payload: {
        status: 500,
        error: 'Internal sensor error'
      }
    });

    const result = await service.searchSessions(tenantId, {});

    expect(result.successfulSensors).toBe(0);
    expect(result.results[0].error).toBe('Internal sensor error');
  });

  it('performs session revocation', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    const sessionId = 'sess-123';
    
    vi.mocked(mockPrisma.sensor.findFirst).mockResolvedValue({ id: sensorId, name: 'Sensor 1' });
    broker.getSensorTunnelInfo.mockReturnValue({ connected: true });
    broker.sendRequest.mockResolvedValue({
      type: 'dashboard-response',
      payload: { status: 200, data: { success: true } }
    });

    const result = await service.revokeSession(tenantId, sensorId, sessionId, 'Abuse');

    expect(result.success).toBe(true);
    expect(broker.sendRequest).toHaveBeenCalledWith(
      sensorId,
      expect.objectContaining({
        payload: expect.objectContaining({
          method: 'DELETE',
          endpoint: `/_sensor/sessions/${sessionId}`
        })
      }),
      expect.any(Number)
    );
  });

  it('performs actor ban via RPC', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    const actorId = '1.2.3.4';
    
    vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([{ id: sensorId, name: 'Sensor 1' }]);
    broker.getSensorTunnelInfo.mockReturnValue({ connected: true });
    broker.sendRequest.mockResolvedValue({
      type: 'dashboard-response',
      payload: { status: 200, data: { success: true, sessionsTerminated: 5 } }
    });

    const result = await service.globalBanActor(tenantId, actorId, 'Malicious', 3600);

    expect(result.successCount).toBe(1);
    expect(result.totalSessionsTerminated).toBe(5);
    expect(broker.sendRequest).toHaveBeenCalledWith(
      sensorId,
      expect.objectContaining({
        payload: expect.objectContaining({
          method: 'POST',
          endpoint: '/_sensor/blocks',
          body: expect.objectContaining({
            value: actorId,
            reason: 'Malicious'
          })
        })
      }),
      expect.any(Number)
    );
  });

  it('uses configured default timeout for sensor RPC calls', async () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';
    const customTimeout = 12_345;

    service = new FleetSessionQueryService({
      prisma: mockPrisma,
      logger: createLogger(),
      tunnelBroker: broker as unknown as TunnelBroker,
      defaultTimeoutMs: customTimeout,
    });

    vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
      { id: sensorId, name: 'Sensor 1' }
    ]);
    broker.getSensorTunnelInfo.mockReturnValue({ connected: true });
    broker.sendRequest.mockResolvedValue({
      type: 'dashboard-response',
      payload: {
        status: 200,
        data: {
          sessions: [],
          totalMatches: 0
        }
      }
    });

    await service.searchSessions(tenantId, {});

    expect(broker.sendRequest).toHaveBeenCalledWith(
      sensorId,
      expect.any(Object),
      customTimeout
    );
  });
});
