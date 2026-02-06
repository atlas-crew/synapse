/**
 * JWT utilities for Signal Horizon.
 * Supports HS256 validation and revocation checks.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { metrics } from '../services/metrics.js';

export type JwtPayload = {
  iat: number;
  exp: number;
  jti?: string;
  tenantId?: string;
  tenant_id?: string;
  sensorId?: string;
  sensor_id?: string;
  userId?: string;
  user_id?: string;
  scopes?: string[];
};

/**
 * Check if token is revoked in database.
 */
export async function isTokenRevoked(
  jti: string,
  tenantId: string,
  prisma: PrismaClient,
  options?: { source?: string; logger?: Logger }
): Promise<boolean> {
  try {
    const entry = await prisma.tokenBlacklist.findUnique({
      where: {
        jti_tenantId: { jti, tenantId },
      },
    });
    return !!entry;
  } catch (error) {
    metrics.authBlacklistDbErrors.inc({ source: options?.source ?? 'unknown' });
    if (options?.logger) {
      options.logger.warn({ error, jti, tenantId }, 'Token revocation check failed');
    }
    // Fail open on DB error to avoid blocking valid traffic.
    // This prioritizes availability but should be monitored via metrics.
    return false;
  }
}

function base64UrlEncode(data: string | Buffer): string {
  return Buffer.from(data)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(data: string): string {
  const padded = data.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (data.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function createSignature(header: string, payload: string, secret: string): string {
  return base64UrlEncode(
    createHmac('sha256', secret).update(`${header}.${payload}`).digest()
  );
}

function verifySignature(header: string, payload: string, signature: string, secret: string): boolean {
  try {
    const expected = createSignature(header, payload, secret);
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length) return false;
    return timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

/**
 * Parses and validates an HS256 JWT.
 */
export function parseJwt(token: string, secret: string): JwtPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts;
  if (!verifySignature(headerB64, payloadB64, signatureB64, secret)) return null;

  try {
    const header = JSON.parse(base64UrlDecode(headerB64));
    if (header.alg !== 'HS256') return null;
    if (header.typ && header.typ !== 'JWT') return null;

    const payload: JwtPayload = JSON.parse(base64UrlDecode(payloadB64));
    if (!payload.iat || !payload.exp) return null;

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) return null;
    // Allow for small clock skew
    if (payload.iat > now + 300) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Signs an HS256 JWT (labs-eyuk).
 */
export function signJwt(payload: JwtPayload, secret: string): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signature = createSignature(headerB64, payloadB64, secret);
  return `${headerB64}.${payloadB64}.${signature}`;
}
