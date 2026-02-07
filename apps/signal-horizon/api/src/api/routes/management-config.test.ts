import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../__tests__/test-request.js';
import { createManagementRoutes } from './management.js';
import { updateFleetCommandFeatures } from '../../services/fleet/command-features.js';

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

const injectAuth = () => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = { tenantId: 'tenant-1', scopes: ['fleet:admin'] } as unknown as typeof req.auth;
    next();
  };
};

describe('Management Config Routes', () => {
  let app: Express;

  beforeEach(() => {
    updateFleetCommandFeatures({ toggleChaos: false, toggleMtd: false });

    app = express();
    app.use(express.json());
    app.use(injectAuth());
    app.use('/api/v1/management', createManagementRoutes({} as PrismaClient, mockLogger));
  });

  it('GET /api/v1/management/config overlays runtime fleetCommands', async () => {
    const res = await request<any>(app)
      .get('/api/v1/management/config')
      .expect(200);

    expect(res.body.fleetCommands).toEqual({
      enableToggleChaos: false,
      enableToggleMtd: false,
    });
  });

  it('PATCH /api/v1/management/config updates runtime fleetCommands', async () => {
    await request<any>(app)
      .patch('/api/v1/management/config')
      .send({ fleetCommands: { enableToggleChaos: true } })
      .expect(200);

    const res = await request<any>(app)
      .get('/api/v1/management/config')
      .expect(200);

    expect(res.body.fleetCommands).toEqual({
      enableToggleChaos: true,
      enableToggleMtd: false,
    });
  });
});

