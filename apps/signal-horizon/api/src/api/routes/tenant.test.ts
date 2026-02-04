/**
 * Tenant Settings API Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createTenantRoutes } from './tenant.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

// Mock Prisma
const mockPrisma = {
  tenant: {
    findUnique: vi.fn(),
    update: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger
const mockLogger = {
  info: vi.fn(),
  error: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

describe('Tenant Settings API', () => {
  let app: express.Express;

  beforeEach(() => {
    vi.clearAllMocks();
    app = express();
    app.use(express.json());
    
    // Mock auth middleware
    app.use((req: any, _res, next) => {
      req.auth = { tenantId: 'tenant-123', userId: 'user-123', scopes: ['fleet:read', 'fleet:write'] };
      next();
    });

    app.use('/tenant', createTenantRoutes(mockPrisma, mockLogger));
  });

  describe('GET /tenant/settings', () => {
    it('should return tenant settings', async () => {
      vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue({
        id: 'tenant-123',
        name: 'Test Tenant',
        tier: 'STANDARD',
        sharingPreference: 'CONTRIBUTE_AND_RECEIVE',
      } as never);

      const response = await request(app).get('/tenant/settings');

      expect(response.status).toBe(200);
      expect(response.body.sharingPreference).toBe('CONTRIBUTE_AND_RECEIVE');
      expect(mockPrisma.tenant.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 'tenant-123' } })
      );
    });

    it('should return 404 if tenant not found', async () => {
      vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue(null as never);

      const response = await request(app).get('/tenant/settings');

      expect(response.status).toBe(404);
    });
  });

  describe('PATCH /tenant/settings', () => {
    it('should update sharing preference', async () => {
      vi.mocked(mockPrisma.tenant.update).mockResolvedValue({
        id: 'tenant-123',
        sharingPreference: 'ISOLATED',
      } as never);

      const response = await request(app)
        .patch('/tenant/settings')
        .send({ sharingPreference: 'ISOLATED' });

      expect(response.status).toBe(200);
      expect(response.body.sharingPreference).toBe('ISOLATED');
      expect(mockPrisma.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'tenant-123' },
          data: { sharingPreference: 'ISOLATED' },
        })
      );
    });

    it('should validate sharing preference values', async () => {
      const response = await request(app)
        .patch('/tenant/settings')
        .send({ sharingPreference: 'INVALID_VALUE' });

      expect(response.status).toBe(400);
      expect(mockPrisma.tenant.update).not.toHaveBeenCalled();
    });
  });
});
