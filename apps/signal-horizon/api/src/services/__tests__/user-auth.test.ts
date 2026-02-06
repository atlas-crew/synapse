import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UserAuthService } from '../user-auth.js';

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
  $transaction: vi.fn().mockImplementation((p) => Promise.all(p)),
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
});