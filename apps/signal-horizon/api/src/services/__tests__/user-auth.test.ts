import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UserAuthService } from '../user-auth.js';

// Mock config before any imports that use it
vi.mock('../../config.js', () => ({
  config: {
    telemetry: {
      jwtSecret: 'test-jwt-secret-minimum-16',
      jwtExpirationSeconds: 3600,
      refreshTokenExpirationSeconds: 604800,
    },
  },
}));

// Mock signJwt so we can inspect payloads
const mockSignJwt = vi.fn().mockReturnValue('mock-access-token');
vi.mock('../../lib/jwt.js', () => ({
  signJwt: (...args: unknown[]) => mockSignJwt(...args),
}));

// Mock scopes
vi.mock('../../api/middleware/scopes.js', () => ({
  ROLE_SCOPES: {
    ADMIN: ['fleet:admin', 'fleet:read', 'fleet:write'],
    OPERATOR: ['fleet:read', 'fleet:write'],
    VIEWER: ['fleet:read'],
  },
}));

// Mock epoch — default to returning 5
const mockGetEpochForTenant = vi.fn().mockResolvedValue(5);
vi.mock('../../lib/epoch.js', () => ({
  getEpochForTenant: (...args: unknown[]) => mockGetEpochForTenant(...args),
}));

// Mocking prisma client
const mockPrisma = {
  user: {
    findUnique: vi.fn(),
  },
  tenantMember: {
    findUnique: vi.fn(),
    findMany: vi.fn(),
  },
  refreshToken: {
    findUnique: vi.fn(),
    create: vi.fn().mockResolvedValue({ id: 'refresh-token-123' }),
    update: vi.fn(),
    updateMany: vi.fn(),
  },
  userSession: {
    create: vi.fn(),
  },
  tokenBlacklist: {
    create: vi.fn(),
  },
  $transaction: vi.fn().mockImplementation((cb) => {
    if (typeof cb === 'function') return cb(mockPrisma);
    return Promise.all(cb);
  }),
};

vi.mock('@prisma/client', () => ({
  PrismaClient: vi.fn().mockImplementation(() => mockPrisma),
  UserRole: {
    VIEWER: 'VIEWER',
    OPERATOR: 'OPERATOR',
    ADMIN: 'ADMIN',
    SUPER_ADMIN: 'SUPER_ADMIN',
  },
}));

describe('UserAuthService', () => {
  let service: UserAuthService;
  let logger: any;

  beforeEach(() => {
    vi.clearAllMocks();
    logger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    } as any;
    service = new UserAuthService(mockPrisma as any, logger);

    // Reset default $transaction mock (supports both array and callback forms)
    mockPrisma.$transaction.mockImplementation((cb: unknown) => {
      if (typeof cb === 'function') return (cb as (p: typeof mockPrisma) => unknown)(mockPrisma);
      return Promise.all(cb as Promise<unknown>[]);
    });

    // Reset default refreshToken.create to return a cuid-like id
    mockPrisma.refreshToken.create.mockResolvedValue({ id: 'refresh-token-123' });
  });

  describe('login', () => {
    it('should authenticate user with correct password', async () => {
      const password = 'Password123!';
      const passwordHash = await service.hashPassword(password);

      const mockUser = {
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
        memberships: [
          {
            tenantId: 'tenant-1',
            role: 'ADMIN',
            tenant: { id: 'tenant-1', name: 'Test Tenant' },
          },
        ],
      };

      mockPrisma.user.findUnique.mockResolvedValue(mockUser);

      const result = await service.login('test@example.com', password);

      expect(result.user.id).toBe('user-1');
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.tenantId).toBe('tenant-1');
      expect(result.role).toBe('ADMIN');
    });

    it('should throw error for invalid password', async () => {
      const passwordHash = await service.hashPassword('correct-password');

      const mockUser = {
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
      };

      mockPrisma.user.findUnique.mockResolvedValue(mockUser);

      await expect(service.login('test@example.com', 'wrong-password')).rejects.toThrow('Invalid email or password');
    });

    it('should reject unknown user', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      await expect(service.login('unknown@example.com', 'some-password')).rejects.toThrow('Invalid email or password');
    });
  });

  describe('getUserTenants', () => {
    it('should return user memberships', async () => {
      const mockMemberships = [
        { tenantId: 'tenant-1', tenant: { name: 'Tenant 1' } },
        { tenantId: 'tenant-2', tenant: { name: 'Tenant 2' } },
      ];

      mockPrisma.tenantMember.findMany.mockResolvedValue(mockMemberships);

      const result = await service.getUserTenants('user-1');

      expect(result).toHaveLength(2);
      expect(result[0].tenantId).toBe('tenant-1');
    });
  });

  // =========================================================================
  // A1: refreshSession lifecycle
  // =========================================================================
  describe('refreshSession', () => {
    // Helpers to build a valid refresh token DB record
    async function buildRefreshTokenRecord(overrides: Record<string, unknown> = {}) {
      const secret = 'test-secret-value-for-refresh';
      const tokenHash = await service.hashPassword(secret);
      const record = {
        id: 'rt-id-1',
        userId: 'user-1',
        tenantId: 'tenant-1',
        tokenHash,
        jti: 'jti-1',
        isRevoked: false,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        user: {
          id: 'user-1',
          memberships: [
            { tenantId: 'tenant-1', role: 'ADMIN' },
          ],
        },
        ...overrides,
      };
      return { record, secret, compositeToken: `${record.id}:${secret}` };
    }

    it('should return new tokens and revoke the old one for a valid refresh token', async () => {
      const { record, compositeToken } = await buildRefreshTokenRecord();
      mockPrisma.refreshToken.findUnique.mockResolvedValue(record);

      const result = await service.refreshSession(compositeToken);

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      // Old token must be revoked (one-time use)
      expect(mockPrisma.refreshToken.update).toHaveBeenCalledWith({
        where: { id: 'rt-id-1' },
        data: { isRevoked: true },
      });
    });

    it('should throw on malformed token (no colon separator)', async () => {
      await expect(service.refreshSession('no-colon-here'))
        .rejects.toThrow('Invalid refresh token format');
    });

    it('should throw when token is not found in the database', async () => {
      mockPrisma.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.refreshSession('unknown-id:some-secret'))
        .rejects.toThrow('Invalid or expired refresh token');
    });

    it('should throw when token is revoked', async () => {
      const { record } = await buildRefreshTokenRecord({ isRevoked: true });
      mockPrisma.refreshToken.findUnique.mockResolvedValue(record);

      await expect(service.refreshSession(`${record.id}:any-secret`))
        .rejects.toThrow('Invalid or expired refresh token');
    });

    it('should throw when token is expired', async () => {
      const { record } = await buildRefreshTokenRecord({
        expiresAt: new Date(Date.now() - 1000), // expired 1 second ago
      });
      mockPrisma.refreshToken.findUnique.mockResolvedValue(record);

      await expect(service.refreshSession(`${record.id}:any-secret`))
        .rejects.toThrow('Invalid or expired refresh token');
    });

    it('should throw when token secret does not match the stored hash', async () => {
      const { record } = await buildRefreshTokenRecord();
      mockPrisma.refreshToken.findUnique.mockResolvedValue(record);

      // Use correct id but wrong secret
      await expect(service.refreshSession(`${record.id}:wrong-secret`))
        .rejects.toThrow('Invalid refresh token');
    });

    it('should throw when user has been removed from the tenant since token was issued', async () => {
      // Build a record where user has NO memberships for tenant-1
      const { record, compositeToken } = await buildRefreshTokenRecord({
        user: {
          id: 'user-1',
          memberships: [
            { tenantId: 'tenant-OTHER', role: 'VIEWER' }, // different tenant
          ],
        },
      });
      mockPrisma.refreshToken.findUnique.mockResolvedValue(record);

      await expect(service.refreshSession(compositeToken))
        .rejects.toThrow('User is no longer a member of this tenant');
    });
  });

  // =========================================================================
  // A2: logout blacklisting
  // =========================================================================
  describe('logout', () => {
    it('should create a blacklist entry with the correct jti and tenantId', async () => {
      await service.logout('jti-abc', 'tenant-1');

      expect(mockPrisma.tokenBlacklist.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            jti: 'jti-abc',
            tenantId: 'tenant-1',
            reason: 'User logout',
          }),
        }),
      );
    });

    it('should revoke refresh tokens matching jti and tenantId', async () => {
      await service.logout('jti-abc', 'tenant-1');

      expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { jti: 'jti-abc', tenantId: 'tenant-1' },
        data: { isRevoked: true },
      });
    });

    it('should perform both blacklist creation and refresh token revocation', async () => {
      await service.logout('jti-xyz', 'tenant-2');

      // Both operations must be called
      expect(mockPrisma.tokenBlacklist.create).toHaveBeenCalledTimes(1);
      expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledTimes(1);

      // Verify blacklist entry
      const blacklistCall = mockPrisma.tokenBlacklist.create.mock.calls[0][0];
      expect(blacklistCall.data.jti).toBe('jti-xyz');
      expect(blacklistCall.data.tenantId).toBe('tenant-2');
      expect(blacklistCall.data.expiresAt).toBeInstanceOf(Date);

      // Verify refresh token revocation
      const revokeCall = mockPrisma.refreshToken.updateMany.mock.calls[0][0];
      expect(revokeCall.where.jti).toBe('jti-xyz');
      expect(revokeCall.where.tenantId).toBe('tenant-2');
      expect(revokeCall.data.isRevoked).toBe(true);
    });
  });

  // =========================================================================
  // A3: switchTenant membership check
  // =========================================================================
  describe('switchTenant', () => {
    it('should return new tokens when user is a member of the target tenant', async () => {
      mockPrisma.tenantMember.findUnique.mockResolvedValue({
        tenantId: 'tenant-2',
        userId: 'user-1',
        role: 'OPERATOR',
      });

      const result = await service.switchTenant('user-1', 'tenant-2');

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(mockPrisma.tenantMember.findUnique).toHaveBeenCalledWith({
        where: { tenantId_userId: { tenantId: 'tenant-2', userId: 'user-1' } },
      });
    });

    it('should throw when user is not a member of the target tenant', async () => {
      mockPrisma.tenantMember.findUnique.mockResolvedValue(null);

      await expect(service.switchTenant('user-1', 'tenant-no-access'))
        .rejects.toThrow('User is not a member of the target tenant');
    });
  });

  // =========================================================================
  // A4: createSession epoch embedding (tested via login)
  // =========================================================================
  describe('createSession epoch', () => {
    async function loginWithMembership(kv?: any) {
      const password = 'EpochTest1!';
      const passwordHash = await service.hashPassword(password);

      const mockUser = {
        id: 'user-epoch',
        email: 'epoch@example.com',
        passwordHash,
        memberships: [
          {
            tenantId: 'tenant-epoch',
            role: 'ADMIN',
            tenant: { id: 'tenant-epoch', name: 'Epoch Tenant' },
          },
        ],
      };

      mockPrisma.user.findUnique.mockResolvedValue(mockUser);

      // Re-instantiate service with or without KV
      const svc = new UserAuthService(mockPrisma as any, logger, kv);
      return svc.login('epoch@example.com', password);
    }

    it('should embed epoch from KV when KV is available', async () => {
      mockGetEpochForTenant.mockResolvedValue(42);

      const mockKv = {} as any; // just needs to be truthy
      await loginWithMembership(mockKv);

      // signJwt should have been called with a payload containing epoch: 42
      expect(mockSignJwt).toHaveBeenCalledWith(
        expect.objectContaining({ epoch: 42 }),
        expect.any(String),
      );
      expect(mockGetEpochForTenant).toHaveBeenCalledWith('tenant-epoch', mockKv);
    });

    it('should default epoch to 0 when KV is not provided', async () => {
      await loginWithMembership(null);

      // signJwt should have been called with epoch: 0
      expect(mockSignJwt).toHaveBeenCalledWith(
        expect.objectContaining({ epoch: 0 }),
        expect.any(String),
      );
      // getEpochForTenant should NOT have been called
      expect(mockGetEpochForTenant).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // A9: login timing-safe on missing user
  // =========================================================================
  describe('timing-safe password verification on missing user', () => {
    it('should still perform password verification when user is null (timing attack mitigation)', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      // Measure that the call does NOT return instantly — it should do
      // scrypt work even when the user is missing.
      // We verify this indirectly: the error message is the same generic
      // "Invalid email or password" (not "User not found"), AND the call
      // takes non-trivial time because scrypt runs against DUMMY_HASH.
      const start = performance.now();
      await expect(service.login('ghost@example.com', 'anything'))
        .rejects.toThrow('Invalid email or password');
      const elapsed = performance.now() - start;

      // scrypt with N=16384,r=8,p=1 on a 64-byte key should take >1ms even
      // on fast hardware. A short-circuit (no hash) would be <0.1ms.
      // Using a generous threshold to avoid flaky CI.
      expect(elapsed).toBeGreaterThan(0.5);

      // Additionally, the warn log should fire with the email (not a
      // "user not found" variant).
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'ghost@example.com' }),
        'Failed login attempt',
      );
    });
  });
});
