/**
 * Fleet Control Routes - P0 Security Tests
 *
 * Validates critical security controls:
 * - Destructive commands (restart/shutdown) require X-Confirm-Token header (428)
 * - Non-destructive commands (reload/drain/resume) proceed without confirm token
 * - Offline sensors (stale heartbeat, disconnected) reject commands (503)
 * - Online sensors (fresh heartbeat or CONNECTED) accept commands (200)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../../__tests__/test-request.js';
import { createFleetControlRoutes } from '../fleet-control.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockPrisma = {
  sensor: {
    findFirst: vi.fn(),
    findMany: vi.fn(),
  },
} as unknown as PrismaClient;

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

/** Auth context with both control and admin scopes */
function attachAuth(req: any, _res: any, next: any): void {
  req.auth = {
    tenantId: 'tenant-1',
    authId: 'api-key-1',
    apiKeyId: 'api-key-1',
    scopes: ['sensor:control', 'sensor:admin'],
    isFleetAdmin: false,
  };
  next();
}

/** Sensor that is online (CONNECTED, fresh heartbeat) */
function onlineSensor() {
  return {
    id: 'sensor-1',
    name: 'Test Sensor',
    connectionState: 'CONNECTED',
    lastHeartbeat: new Date(),
    tunnelActive: false,
  };
}

/** Sensor that is offline (DISCONNECTED, heartbeat 5 min ago) */
function offlineSensor() {
  return {
    id: 'sensor-1',
    name: 'Test Sensor',
    connectionState: 'DISCONNECTED',
    lastHeartbeat: new Date(Date.now() - 300_000),
    tunnelActive: false,
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Fleet Control Routes - Security', () => {
  let app: Express;

  beforeEach(() => {
    vi.clearAllMocks();

    app = express();
    app.use(express.json());
    app.use(attachAuth);

    const router = createFleetControlRoutes(mockPrisma, mockLogger);
    app.use('/fleet-control', router);
  });

  // -------------------------------------------------------------------------
  // Destructive command confirmation (428 PRECONDITION_REQUIRED)
  // -------------------------------------------------------------------------

  describe('Destructive command confirmation', () => {
    it('rejects restart without X-Confirm-Token with 428', async () => {
      const res = await request(app)
        .post('/fleet-control/sensor-1/control/restart')
        .send({})
        .expect(428);

      expect(res.body.error).toBe('Confirmation required');
      expect(res.body.command).toBe('restart');
    });

    it('rejects shutdown without X-Confirm-Token with 428', async () => {
      const res = await request(app)
        .post('/fleet-control/sensor-1/control/shutdown')
        .send({})
        .expect(428);

      expect(res.body.error).toBe('Confirmation required');
      expect(res.body.command).toBe('shutdown');
    });

    it('proceeds with restart when X-Confirm-Token is provided and sensor is online', async () => {
      vi.mocked(mockPrisma.sensor.findFirst).mockResolvedValue(onlineSensor() as any);

      const res = await request(app)
        .post('/fleet-control/sensor-1/control/restart')
        .set('x-confirm-token', 'confirm-abc-123')
        .send({})
        .expect(200);

      expect(res.body.command).toBe('restart');
      expect(res.body.success).toBe(true);
      expect(res.body.sensorId).toBe('sensor-1');
    });
  });

  // -------------------------------------------------------------------------
  // Non-destructive commands (no confirmation needed)
  // -------------------------------------------------------------------------

  describe('Non-destructive commands', () => {
    it('allows reload without X-Confirm-Token (200)', async () => {
      vi.mocked(mockPrisma.sensor.findFirst).mockResolvedValue(onlineSensor() as any);

      const res = await request(app)
        .post('/fleet-control/sensor-1/control/reload')
        .send({})
        .expect(200);

      expect(res.body.command).toBe('reload');
      expect(res.body.success).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Sensor online/offline gating (503 SERVICE_UNAVAILABLE)
  // -------------------------------------------------------------------------

  describe('Sensor availability', () => {
    it('returns 503 when sensor is offline and heartbeat is stale', async () => {
      vi.mocked(mockPrisma.sensor.findFirst).mockResolvedValue(offlineSensor() as any);

      const res = await request(app)
        .post('/fleet-control/sensor-1/control/restart')
        .set('x-confirm-token', 'confirm-abc-123')
        .send({})
        .expect(503);

      expect(res.body.error).toBe('Sensor offline');
      expect(res.body.sensorId).toBe('sensor-1');
    });

    it('returns 200 when sensor is online with fresh heartbeat', async () => {
      vi.mocked(mockPrisma.sensor.findFirst).mockResolvedValue(onlineSensor() as any);

      const res = await request(app)
        .post('/fleet-control/sensor-1/control/restart')
        .set('x-confirm-token', 'confirm-abc-123')
        .send({})
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.sensorName).toBe('Test Sensor');
    });
  });
});
