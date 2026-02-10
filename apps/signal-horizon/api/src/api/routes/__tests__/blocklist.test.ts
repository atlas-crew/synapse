/**
 * Blocklist Routes - P0 Security Tests
 *
 * Validates critical authorization controls:
 * - Fleet-wide block creation requires isFleetAdmin (403)
 * - Fleet-wide block deletion requires isFleetAdmin (403)
 * - Fleet admins can create and delete fleet-wide blocks
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { PrismaClient } from '@prisma/client';
import request from '../../../__tests__/test-request.js';
import { createBlocklistRoutes } from '../blocklist.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockPrisma = {
  blocklistEntry: {
    findMany: vi.fn(),
    count: vi.fn(),
    upsert: vi.fn(),
    findUnique: vi.fn(),
    findFirst: vi.fn(),
    delete: vi.fn(),
  },
} as unknown as PrismaClient;

/** Non-admin with blocklist:write (passes scope gate but not fleet-admin check) */
function attachNonAdminAuth(req: any, _res: any, next: any): void {
  req.auth = {
    tenantId: 'tenant-1',
    authId: 'k1',
    apiKeyId: 'k1',
    scopes: ['blocklist:write'],
    isFleetAdmin: false,
  };
  next();
}

/** Fleet admin with full privileges */
function attachFleetAdminAuth(req: any, _res: any, next: any): void {
  req.auth = {
    tenantId: 'tenant-1',
    authId: 'k1',
    apiKeyId: 'k1',
    scopes: ['fleet:admin', 'blocklist:write'],
    isFleetAdmin: true,
  };
  next();
}

/** Helper to build an Express app with the given auth middleware */
function buildApp(authMiddleware: (...args: any[]) => void): Express {
  const app = express();
  app.use(express.json());
  app.use(authMiddleware);
  app.use('/blocklist', createBlocklistRoutes(mockPrisma));
  return app;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Blocklist Routes - Security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // Fleet-wide block creation
  // -------------------------------------------------------------------------

  describe('Fleet-wide block creation', () => {
    it('rejects fleetWide=true from non-fleet-admin with 403', async () => {
      const app = buildApp(attachNonAdminAuth);

      const res = await request(app)
        .post('/blocklist')
        .send({
          blockType: 'IP',
          indicator: '10.0.0.1',
          reason: 'Testing',
          fleetWide: true,
        })
        .expect(403);

      expect(res.body.error).toBe('Only fleet admins can create fleet-wide blocks');
    });

    it('allows fleetWide=true from fleet admin with 201', async () => {
      const app = buildApp(attachFleetAdminAuth);

      const mockEntry = {
        id: 'block-1',
        blockType: 'IP',
        indicator: '10.0.0.1',
        tenantId: null,
        source: 'MANUAL',
        reason: 'Testing',
        propagationStatus: 'PENDING',
        createdAt: new Date().toISOString(),
      };

      vi.mocked(mockPrisma.blocklistEntry.upsert).mockResolvedValue(mockEntry as any);

      const res = await request(app)
        .post('/blocklist')
        .send({
          blockType: 'IP',
          indicator: '10.0.0.1',
          reason: 'Testing',
          fleetWide: true,
        })
        .expect(201);

      expect(res.body.id).toBe('block-1');
      expect(res.body.tenantId).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // Fleet-wide block deletion
  // -------------------------------------------------------------------------

  describe('Fleet-wide block deletion', () => {
    /** A fleet-wide block has tenantId: null */
    const fleetWideEntry = {
      id: '550e8400-e29b-41d4-a716-446655440000',
      blockType: 'IP',
      indicator: '10.0.0.1',
      tenantId: null,
      source: 'MANUAL',
    };

    it('rejects deletion of fleet-wide block by non-fleet-admin with 403', async () => {
      const app = buildApp(attachNonAdminAuth);

      vi.mocked(mockPrisma.blocklistEntry.findUnique).mockResolvedValue(fleetWideEntry as any);

      const res = await request(app)
        .delete(`/blocklist/${fleetWideEntry.id}`)
        .expect(403);

      expect(res.body.error).toBe('Only fleet admins can delete fleet-wide blocks');
      // Verify delete was never called
      expect(mockPrisma.blocklistEntry.delete).not.toHaveBeenCalled();
    });

    it('allows deletion of fleet-wide block by fleet admin with 204', async () => {
      const app = buildApp(attachFleetAdminAuth);

      vi.mocked(mockPrisma.blocklistEntry.findUnique).mockResolvedValue(fleetWideEntry as any);
      vi.mocked(mockPrisma.blocklistEntry.delete).mockResolvedValue(fleetWideEntry as any);

      await request(app)
        .delete(`/blocklist/${fleetWideEntry.id}`)
        .expect(204);

      expect(mockPrisma.blocklistEntry.delete).toHaveBeenCalledWith({
        where: { id: fleetWideEntry.id },
      });
    });
  });
});
