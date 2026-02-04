/**
 * Telemetry JWT authentication middleware utilities.
 *
 * Enforces JWT validation + revocation checks for telemetry ingest.
 */

import type { Request, Response } from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from '../../config.js';

export interface TelemetryAuthContext {
  tenantId: string;
  sensorId: string;
  jti: string;
}

type JwtPayload = {
  iat: number;
  exp: number;
  jti?: string;
  tenantId?: string;
  tenant_id?: string;
  sensorId?: string;
  sensor_id?: string;
};

const tokenBlacklist = new Map<string, number>();
const BLACKLIST_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

function cleanupBlacklist(): void {
  const now = Date.now();
  for (const [jti, expiresAt] of tokenBlacklist.entries()) {
    if (now > expiresAt) {
      tokenBlacklist.delete(jti);
    }
  }
}

setInterval(cleanupBlacklist, BLACKLIST_CLEANUP_INTERVAL_MS).unref();

export function revokeTelemetryToken(jti: string, expiresAtSeconds?: number): void {
  if (!jti) return;
  const fallbackExpiry = Date.now() + 24 * 60 * 60 * 1000;
  const expiresAt = typeof expiresAtSeconds === 'number'
    ? Math.max(Date.now(), expiresAtSeconds * 1000)
    : fallbackExpiry;
  tokenBlacklist.set(jti, expiresAt);
}

export function isTelemetryTokenRevoked(jti: string): boolean {
  const expiresAt = tokenBlacklist.get(jti);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    tokenBlacklist.delete(jti);
    return false;
  }
  return true;
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
  const expected = createSignature(header, payload, secret);
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return false;
  return timingSafeEqual(sigBuf, expBuf);
}

function parseTelemetryJwt(token: string, secret: string): JwtPayload | null {
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
    if (payload.iat > now + 60) return null;

    return payload;
  } catch {
    return null;
  }
}

export function requireTelemetryJwt(req: Request, res: Response): TelemetryAuthContext | null {
  const secret = config.telemetry.jwtSecret;
  if (!secret) {
    res.status(503).json({ error: 'telemetry_jwt_missing' });
    return null;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }

  const token = authHeader.slice(7).trim();
  const payload = parseTelemetryJwt(token, secret);
  if (!payload) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }

  if (!payload.jti) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }

  if (isTelemetryTokenRevoked(payload.jti)) {
    res.status(401).json({ error: 'token_revoked' });
    return null;
  }

  const tenantId = payload.tenantId ?? payload.tenant_id;
  const sensorId = payload.sensorId ?? payload.sensor_id;
  if (!tenantId || !sensorId) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }

  return { tenantId, sensorId, jti: payload.jti };
}
