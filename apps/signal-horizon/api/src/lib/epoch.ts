/**
 * Epoch-based Token Revocation (labs-wqy1)
 *
 * Provides tenant-scoped epoch management for bulk token invalidation.
 * When a tenant's epoch is incremented, all JWTs issued with a lower epoch
 * are considered expired, enabling "revoke all tokens" functionality.
 *
 * Uses the RedisKv abstraction for storage. Throws on Redis errors so that
 * callers (auth middleware) can fail-closed with 503 rather than silently
 * bypassing revocation.
 */

import { type RedisKv } from '../storage/redis/kv.js';
import { buildRedisKey } from '../storage/redis/keys.js';

const EPOCH_NAMESPACE = 'horizon';
const EPOCH_VERSION = 1;
const EPOCH_DATA_TYPE = 'auth-epoch';
const EPOCH_ID = 'current';

function epochKey(tenantId: string): string {
  return buildRedisKey({
    namespace: EPOCH_NAMESPACE,
    version: EPOCH_VERSION,
    tenantId,
    dataType: EPOCH_DATA_TYPE,
    id: EPOCH_ID,
  });
}

/**
 * Error thrown when Redis is unavailable during epoch lookup.
 * Callers should treat this as a denial (503) rather than allowing access.
 */
export class EpochLookupError extends Error {
  public readonly cause: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'EpochLookupError';
    this.cause = cause;
  }
}

/**
 * Get the current epoch for a tenant.
 * Returns 0 if no epoch has been set (tenant has never revoked tokens).
 * Throws EpochLookupError on Redis errors so the auth middleware can
 * respond with 503 instead of silently bypassing revocation.
 */
export async function getEpochForTenant(
  tenantId: string,
  kv: RedisKv
): Promise<number> {
  try {
    const raw = await kv.get(epochKey(tenantId));
    if (raw === null) return 0;
    const parsed = parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  } catch (error) {
    throw new EpochLookupError(
      `Failed to read auth epoch for tenant ${tenantId}`,
      error
    );
  }
}

/**
 * Atomically increment the epoch for a tenant and return the new value.
 * This effectively invalidates all tokens issued before this epoch.
 *
 * Uses Redis INCR for atomicity -- the previous read-modify-write pattern
 * was susceptible to lost updates under concurrent revocation requests.
 */
export async function incrementEpochForTenant(
  tenantId: string,
  kv: RedisKv
): Promise<number> {
  return kv.incr(epochKey(tenantId));
}
