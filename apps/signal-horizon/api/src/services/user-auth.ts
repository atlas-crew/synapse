import type { PrismaClient, User, TenantMember, UserRole } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID, scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { signJwt, type JwtPayload } from '../lib/jwt.js';
import { config } from '../config.js';
import { ROLE_SCOPES } from '../api/middleware/scopes.js';

const scryptAsync = promisify(scrypt);

export interface LoginResult {
  user: Omit<User, 'passwordHash'>;
  accessToken: string;
  refreshToken: string;
  tenantId: string;
  role: UserRole;
}

export class UserAuthService {
  constructor(private prisma: PrismaClient, private logger: Logger) {}

  /**
   * Authenticate user and create a session.
   */
  async login(email: string, passwordPlain: string, metadata?: { ip?: string; ua?: string }): Promise<LoginResult> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { memberships: { include: { tenant: true } } },
    });

    if (!user || !(await this.verifyPassword(passwordPlain, user.passwordHash))) {
      this.logger.warn({ email, ip: metadata?.ip }, 'Failed login attempt');
      throw new Error('Invalid email or password');
    }

    if (user.memberships.length === 0) {
      this.logger.warn({ userId: user.id, email }, 'User has no tenant memberships');
      throw new Error('User has no tenant memberships');
    }

    // Default to first tenant for initial login
    const membership = user.memberships[0];
    const tokens = await this.createSession(user.id, membership.tenantId, membership.role, metadata);

    this.logger.info({ userId: user.id, tenantId: membership.tenantId }, 'User logged in successfully');

    const { passwordHash, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      ...tokens,
      tenantId: membership.tenantId,
      role: membership.role,
    };
  }

  /**
   * Create a new access token using a refresh token.
   */
  async refreshSession(refreshTokenStr: string, metadata?: { ip?: string; ua?: string }): Promise<{ accessToken: string, refreshToken: string }> {
    const tokenHash = createHash('sha256').update(refreshTokenStr).digest('hex');
    const refreshToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: { include: { memberships: true } } },
    });

    if (!refreshToken || refreshToken.isRevoked || refreshToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired refresh token');
    }

    const membership = refreshToken.user.memberships.find(m => m.tenantId === refreshToken.tenantId);
    if (!membership) {
      throw new Error('User is no longer a member of this tenant');
    }

    // Revoke old refresh token (one-time use)
    await this.prisma.refreshToken.update({
      where: { id: refreshToken.id },
      data: { isRevoked: true },
    });

    this.logger.debug({ userId: refreshToken.userId, tenantId: refreshToken.tenantId }, 'Session refreshed');

    // Create new session
    return this.createSession(refreshToken.userId, refreshToken.tenantId, membership.role, metadata);
  }

  /**
   * Switch active tenant context.
   */
  async switchTenant(userId: string, tenantId: string, metadata?: { ip?: string; ua?: string }): Promise<{ accessToken: string, refreshToken: string }> {
    const membership = await this.prisma.tenantMember.findUnique({
      where: { tenantId_userId: { tenantId, userId } },
    });

    if (!membership) {
      throw new Error('User is not a member of the target tenant');
    }

    this.logger.info({ userId, tenantId }, 'User switched tenant context');

    // Create new session for target tenant
    return this.createSession(userId, tenantId, membership.role, metadata);
  }

  /**
   * Revoke a session.
   */
  async logout(jti: string, tenantId: string): Promise<void> {
    this.logger.info({ jti, tenantId }, 'User logout');

    // Blacklist the JTI
    await this.prisma.tokenBlacklist.create({
      data: {
        jti,
        tenantId,
        reason: 'User logout',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    // Revoke associated refresh token(s)
    await this.prisma.refreshToken.updateMany({
      where: { jti, tenantId },
      data: { isRevoked: true },
    });
  }

  /**
   * Get all tenants a user is a member of.
   */
  async getUserTenants(userId: string) {
    return this.prisma.tenantMember.findMany({
      where: { userId },
      include: { tenant: { select: { id: true, name: true, shortId: true } } },
    });
  }

  /**
   * Securely hash a password.
   */
  async hashPassword(password: string): Promise<string> {
    const salt = randomBytes(16).toString('hex');
    const buf = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${salt}:${buf.toString('hex')}`;
  }

  // =========================================================================
  // Private Helpers
  // =========================================================================

  private async createSession(
    userId: string, 
    tenantId: string, 
    role: UserRole, 
    metadata?: { ip?: string; ua?: string }
  ): Promise<{ accessToken: string, refreshToken: string }> {
    const jti = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const accessTokenExp = now + (config.telemetry.jwtExpirationSeconds || 3600);
    const refreshTokenExp = now + (config.telemetry.refreshTokenExpirationSeconds || 86400 * 7);

    // Get scopes for role
    const scopes = ROLE_SCOPES[role] || [];

    const accessPayload: JwtPayload = {
      iat: now,
      exp: accessTokenExp,
      jti,
      userId,
      tenantId,
      scopes,
    };

    const accessToken = signJwt(accessPayload, config.telemetry.jwtSecret || 'dev-secret-do-not-use-in-prod');

    const refreshTokenStr = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(refreshTokenStr).digest('hex');

    await this.prisma.$transaction([
      this.prisma.userSession.create({
        data: {
          userId,
          tenantId,
          jti,
          expiresAt: new Date(accessTokenExp * 1000),
          ipAddress: metadata?.ip,
          userAgent: metadata?.ua,
        },
      }),
      this.prisma.refreshToken.create({
        data: {
          userId,
          tenantId,
          tokenHash,
          jti,
          expiresAt: new Date(refreshTokenExp * 1000),
        },
      }),
    ]);

    return { accessToken, refreshToken: refreshTokenStr };
  }

  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      const [salt, key] = hash.split(':');
      if (!salt || !key) return false;
      const keyBuf = Buffer.from(key, 'hex');
      const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer;
      return timingSafeEqual(keyBuf, derivedKey);
    } catch {
      return false;
    }
  }
}
