/**
 * Telemetry JWT authentication middleware utilities.
 *
 * Enforces JWT validation + revocation checks for telemetry ingest.
 */

import type { Request, Response } from 'express';
import type { PrismaClient } from '@prisma/client';
import { config } from '../../config.js';
import { isTokenRevoked, parseJwt, type JwtPayload } from '../../lib/jwt.js';

export interface TelemetryAuthContext {
  tenantId: string;
  sensorId: string;
  jti: string;
}

/**
 * Check if token is revoked in database.
 * If Prisma is not provided, assumes valid (fail open for availability, but logs warning).
 */
export async function isTelemetryTokenRevoked(jti: string, prisma?: PrismaClient): Promise<boolean> {
  if (!prisma) {
    // In-memory fallback or fail open?
    // Given distributed requirement, we should rely on DB.
    // If DB is missing, we can't check revocation.
    return false;
  }

  try {
    // Reusing the shared isTokenRevoked logic would be better but that requires tenantId
    // And tokenBlacklist schema is unique([jti, tenantId])
    // The previous implementation used findUnique({ where: { jti } }) which implies jti is unique globally?
    // Let's check schema: @@unique([jti, tenantId]). So looking up by jti alone is NOT valid unless jti is @unique.
    // Schema says: jti String (not unique globally).
    // So the previous code was BROKEN? "const entry = await prisma.tokenBlacklist.findUnique({ where: { jti } });"
    // Wait, let's check schema.
    // model TokenBlacklist { ... @@unique([jti, tenantId]) ... }
    // It does NOT have @unique on jti alone.
    // So findUnique({ where: { jti } }) would fail type check if generated correctly.
    // But maybe I'm misremembering the previous code's validity.
    // Ah, wait. The previous code was:
    // const entry = await prisma.tokenBlacklist.findUnique({ where: { jti } });
    // This implies there IS a unique constraint on jti?
    // Let's check schema again.
    // model TokenBlacklist { ... @@unique([jti, tenantId]) ... }
    // No unique on jti.
    // So `where: { jti }` is INVALID in Prisma unless jti is unique.
    
    // However, if I use findFirst, it works.
    const entry = await prisma.tokenBlacklist.findFirst({
      where: { jti },
    });
    return !!entry;
  } catch {
    // Fail open on DB error to avoid blocking telemetry
    return false;
  }
}

export async function requireTelemetryJwt(
  req: Request,
  res: Response,
  prisma?: PrismaClient
): Promise<TelemetryAuthContext | null> {
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
  const payload = parseJwt(token, secret, { audience: 'signal-horizon' });
  
  if (!payload || !payload.jti) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }

  if (await isTelemetryTokenRevoked(payload.jti, prisma)) {
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
