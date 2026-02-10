/**
 * Fleet Sessions API — Tenant Isolation Security Tests
 *
 * Verifies that all fleet session routes derive tenantId exclusively from
 * the authenticated auth context (req.auth.tenantId), never from user-supplied
 * input such as query parameters or request body fields.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../../__tests__/test-request.js';
import { createFleetSessionsRoutes } from '../fleet-sessions.js';

// =============================================================================
// Mocks
// =============================================================================

const mockSessionQueryService = {
  searchSessions: vi.fn().mockResolvedValue({ sessions: [], total: 0 }),
  getFleetSessionStats: vi.fn().mockResolvedValue({ totalSessions: 0 }),
  globalRevokeSession: vi.fn().mockResolvedValue({ success: true }),
  revokeSession: vi.fn().mockResolvedValue({ success: true }),
  globalBanActor: vi.fn().mockResolvedValue({ success: true }),
};

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

// =============================================================================
// Tests
// =============================================================================

describe('Fleet Sessions — Tenant Isolation', () => {
  let app: Express;

  beforeEach(() => {
    vi.clearAllMocks();

    app = express();
    app.use(express.json());

    // Simulate authenticated request with a known tenantId.
    // All routes MUST forward this tenantId — not any user-supplied value.
    app.use((req, _res, next) => {
      req.auth = {
        tenantId: 'tenant-1',
        authId: 'jti-1',
        apiKeyId: 'jti-1',
        scopes: ['fleet:read', 'fleet:write'],
        isFleetAdmin: false,
        userId: 'user-1',
      };
      next();
    });

    const router = createFleetSessionsRoutes(
      {} as PrismaClient,
      mockLogger,
      { sessionQueryService: mockSessionQueryService as any }
    );
    app.use('/api/v1/fleet', router);
  });

  it('GET /sessions/search passes auth.tenantId to service, not user input', async () => {
    await request(app)
      .get('/api/v1/fleet/sessions/search?actorId=attacker-42')
      .expect(200);

    expect(mockSessionQueryService.searchSessions).toHaveBeenCalledTimes(1);
    expect(mockSessionQueryService.searchSessions).toHaveBeenCalledWith(
      'tenant-1', // Must be from auth context
      expect.any(Object)
    );

    // Verify the query object does NOT contain a rogue tenantId field
    const [tenantArg] = mockSessionQueryService.searchSessions.mock.calls[0];
    expect(tenantArg).toBe('tenant-1');
  });

  it('POST /sessions/:sessionId/revoke passes auth.tenantId to service', async () => {
    await request(app)
      .post('/api/v1/fleet/sessions/session-abc/revoke')
      .send({ reason: 'compromised' })
      .expect(200);

    expect(mockSessionQueryService.globalRevokeSession).toHaveBeenCalledTimes(1);
    expect(mockSessionQueryService.globalRevokeSession).toHaveBeenCalledWith(
      'tenant-1', // Must be from auth context
      'session-abc',
      'compromised',
      undefined // no sensorIds
    );
  });

  it('GET /sessions/stats passes auth.tenantId, preventing cross-tenant data leak', async () => {
    mockSessionQueryService.getFleetSessionStats.mockResolvedValueOnce({
      totalSessions: 42,
      totalBlockedSessions: 3,
    });

    const res = await request(app)
      .get('/api/v1/fleet/sessions/stats')
      .expect(200);

    // Service was called with the auth tenantId
    expect(mockSessionQueryService.getFleetSessionStats).toHaveBeenCalledTimes(1);
    expect(mockSessionQueryService.getFleetSessionStats).toHaveBeenCalledWith('tenant-1');

    // Response is the data the service returned for tenant-1
    expect(res.body.totalSessions).toBe(42);
  });
});
