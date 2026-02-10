import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import express, { type Express } from 'express';
import { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../../__tests__/test-request.js';
import { createAuthRoutes, consumeWsTicket } from '../auth.js';
import { UserAuthService } from '../../../services/user-auth.js';

// Mock Config
const mockConfig = vi.hoisted(() => ({
  isDev: true,
  telemetry: {
    jwtExpirationSeconds: 3600,
    jwtSecret: 'test-secret',
  },
}));

vi.mock('../../../config.js', () => ({
  config: mockConfig,
}));

describe('Auth Routes', () => {
  let app: Express;
  let prisma: PrismaClient;
  let logger: Logger;
  let userAuthService: UserAuthService;

  beforeEach(() => {
    vi.clearAllMocks();
    mockConfig.isDev = true;

    prisma = {
      tenant: {
        findFirst: vi.fn(),
        create: vi.fn().mockResolvedValue({ id: 'tenant-1', name: 'Dev Tenant' }),
      },
      apiKey: {
        upsert: vi.fn(),
      },
      user: {
        findUnique: vi.fn(),
      },
    } as unknown as PrismaClient;

    logger = {
      warn: vi.fn(),
      info: vi.fn(),
      child: vi.fn().mockReturnThis(),
    } as unknown as Logger;

    userAuthService = {
      login: vi.fn(),
      refreshSession: vi.fn(),
      logout: vi.fn(),
      getUserTenants: vi.fn(),
      switchTenant: vi.fn(),
    } as unknown as UserAuthService;

    const authMiddleware = (req: any, _res: any, next: any) => {
      // simulate authenticated user for protected routes
      req.auth = {
        userId: 'user-1',
        tenantId: 'tenant-1',
        scopes: ['hunt:read'],
        authId: 'jti-1'
      };
      next();
    };

    app = express();
    app.use(express.json());
    app.use('/api/v1/auth', createAuthRoutes(prisma, logger, userAuthService, authMiddleware));
  });

  describe('WebSocket Ticket System', () => {
    it('generates, consumes, and expires tickets', async () => {
      // 1. Get a ticket
      const res = await request(app)
        .get('/api/v1/auth/ws-ticket')
        .expect(200);

      const { ticket } = res.body;
      expect(ticket).toBeDefined();

      // 2. Consume it
      const payload = consumeWsTicket(ticket);
      expect(payload).toMatchObject({
        userId: 'user-1',
        tenantId: 'tenant-1',
      });

      // 3. Second use should fail (one-time use)
      const payload2 = consumeWsTicket(ticket);
      expect(payload2).toBeNull();
    });

    it('rejects expired tickets', async () => {
      vi.useFakeTimers();
      
      const res = await request(app)
        .get('/api/v1/auth/ws-ticket')
        .expect(200);

      const { ticket } = res.body;
      
      // Advance time past 30s TTL
      vi.advanceTimersByTime(31000);

      const payload = consumeWsTicket(ticket);
      expect(payload).toBeNull();

      vi.useRealTimers();
    });
  });

  describe('GET /dev/bootstrap', () => {
    it('returns 404 if not in dev mode', async () => {
      mockConfig.isDev = false;
      await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .expect(404);
    });

    it('returns 403 if not from loopback IP', async () => {
      await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .set('X-Forwarded-For', '1.1.1.1')
        .expect(403);
    });

    it('mints a cookie-based API key on localhost', async () => {
      vi.mocked(prisma.tenant.findFirst).mockResolvedValue(null); // Force creation

      const res = await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .set('X-Forwarded-For', '127.0.0.1')
        .expect(200);

      expect(res.body.ok).toBe(true);
      // test-request collapses headers into string
      expect(res.headers['set-cookie']).toContain('horizon_api_key=dev_');
      expect(prisma.apiKey.upsert).toHaveBeenCalled();
    });

    it('allows IPv6 loopback (::1)', async () => {
      vi.mocked(prisma.tenant.findFirst).mockResolvedValue(null);

      const res = await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .set('X-Forwarded-For', '::1')
        .expect(200);

      expect(res.body.ok).toBe(true);
    });

    it('allows IPv4-mapped IPv6 (::ffff:127.0.0.1) after prefix strip', async () => {
      vi.mocked(prisma.tenant.findFirst).mockResolvedValue(null);

      const res = await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .set('X-Forwarded-For', '::ffff:127.0.0.1')
        .expect(200);

      expect(res.body.ok).toBe(true);
    });

    it('returns 403 for private non-loopback IP (10.0.0.1)', async () => {
      await request(app)
        .get('/api/v1/auth/dev/bootstrap')
        .set('X-Forwarded-For', '10.0.0.1')
        .expect(403);
    });
  });

  describe('POST /login', () => {
    it('sets access_token cookie and returns user info', async () => {
      const mockUser = { id: 'u1', email: 'test@example.com', name: 'Test User' };
      vi.mocked(userAuthService.login).mockResolvedValue({
        user: mockUser,
        accessToken: 'signed-jwt',
        refreshToken: 'refresh-id:secret',
        tenantId: 't1',
        role: 'user'
      } as any);

      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'test@example.com', password: 'password' })
        .expect(200);

      // Verify cookie - test-request collapses headers
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies).toContain('access_token=signed-jwt');
      expect(cookies).toContain('HttpOnly');

      // Verify body doesn't contain accessToken but contains everything else
      expect(res.body.accessToken).toBeUndefined();
      expect(res.body.refreshToken).toBe('refresh-id:secret');
      expect(res.body.user).toEqual(mockUser);
    });

    it('returns 401 on service failure', async () => {
      vi.mocked(userAuthService.login).mockRejectedValue(new Error('Invalid email or password'));

      await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'bad@example.com', password: 'wrong' })
        .expect(401);
    });
  });

  describe('GET /me', () => {
    it('returns user details for authenticated request', async () => {
      vi.mocked(prisma.user.findUnique).mockResolvedValue({
        id: 'user-1',
        email: 'user1@example.com',
        name: 'User One',
        createdAt: new Date(),
      } as any);

      const res = await request(app)
        .get('/api/v1/auth/me')
        .expect(200);

      expect(res.body.email).toBe('user1@example.com');
      expect(res.body.tenantId).toBe('tenant-1');
      expect(res.body.scopes).toContain('hunt:read');
    });
  });
});
