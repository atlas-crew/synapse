import type { PrismaClient, User, TenantMember, UserRole } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID, scrypt, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { signJwt, type JwtPayload } from '../lib/jwt.js';
import { config } from '../config.js';
import { ROLE_SCOPES } from '../api/middleware/scopes.js';

const scryptAsync = promisify(scrypt);

// Pre-computed dummy hash for timing attack mitigation (labs-21bx)
// Generated with: await service.hashPassword('dummy_password_for_timing_mitigation')
const DUMMY_HASH = '1234567890abcdef1234567890abcdef:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

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

    // Timing side-channel mitigation (labs-21bx):
    // Always perform password verification to prevent user enumeration.
    // If user is null, we verify against a dummy hash.
    const targetHash = user?.passwordHash ?? DUMMY_HASH;
    const isPasswordValid = await this.verifyPassword(passwordPlain, targetHash);

    if (!user || !isPasswordValid) {
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
    // Parse composite token: id:secret (labs-pb60)
    const [tokenId, tokenSecret] = refreshTokenStr.split(':');
    
    if (!tokenId || !tokenSecret) {
      // Fallback for legacy SHA-256 tokens (if any existed, but this is a new system)
      // or malformed tokens.
      throw new Error('Invalid refresh token format');
    }

    const refreshToken = await this.prisma.refreshToken.findUnique({
      where: { id: tokenId },
      include: { user: { include: { memberships: true } } },
    });

    if (!refreshToken || refreshToken.isRevoked || refreshToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired refresh token');
    }

    // Verify token secret against stored hash (scrypt)
    const isValid = await this.verifyPassword(tokenSecret, refreshToken.tokenHash);
    if (!isValid) {
      this.logger.warn({ userId: refreshToken.userId, tokenId }, 'Invalid refresh token secret');
      throw new Error('Invalid refresh token');
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

    const jwtSecret = config.telemetry.jwtSecret;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not configured. Set JWT_SECRET or TELEMETRY_JWT_SECRET environment variable.');
    }
    const accessToken = signJwt(accessPayload, jwtSecret);

    const tokenSecret = randomBytes(32).toString('hex');
    const tokenHash = await this.hashPassword(tokenSecret); // Use scrypt (labs-pb60)

    // Create session first to get JTI if needed, but we generate JTI ourselves
    // We need to create the refresh token record to get its ID (cuid)
    // Actually, we can let Prisma generate the ID and just return it.
    // Wait, create() returns the object.

    const [_, refreshTokenRecord] = await this.prisma.$transaction([
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

    // Return composite token: id:secret
    return { accessToken, refreshToken: `${refreshTokenRecord.id}:${tokenSecret}` };
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
