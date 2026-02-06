/**
 * Replay Attack Protection Middleware
 *
 * Prevents replay attacks by validating request nonces and timestamps.
 * Uses a sliding window approach with automatic cleanup of expired nonces.
 *
 * @module replay-protection
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

// =============================================================================
// Types
// =============================================================================

/**
 * Configuration for replay protection.
 */
export interface ReplayProtectionConfig {
  /** Time window for valid requests (ms) */
  windowMs: number;
  /** Header name for request nonce */
  nonceHeader: string;
  /** Header name for request timestamp */
  timestampHeader: string;
  /** Maximum allowed clock drift (ms) */
  maxTimeDrift: number;
  /** Routes to skip protection (exact match or regex) */
  skipRoutes?: (string | RegExp)[];
  /** HTTP methods to skip (e.g., GET, HEAD) */
  skipMethods?: string[];
}

/**
 * Error codes for replay protection failures.
 */
export type ReplayProtectionError =
  | 'missing_nonce'
  | 'missing_timestamp'
  | 'invalid_nonce_format'
  | 'invalid_timestamp_format'
  | 'timestamp_expired'
  | 'timestamp_future'
  | 'nonce_reused';

/**
 * Result of replay protection validation.
 */
export interface ReplayProtectionResult {
  /** Whether the request is valid */
  valid: boolean;
  /** Error code if invalid */
  error?: ReplayProtectionError;
  /** Human-readable error message */
  message?: string;
}

/**
 * Metadata stored with each nonce.
 */
interface NonceMetadata {
  /** Request timestamp */
  timestamp: number;
  /** When this nonce expires */
  expiresAt: number;
  /** Client IP (for logging) */
  clientIp?: string;
  /** Request path (for logging) */
  path?: string;
}

// =============================================================================
// Default Configuration
// =============================================================================

/**
 * Default replay protection configuration.
 */
export const DEFAULT_REPLAY_CONFIG: ReplayProtectionConfig = {
  windowMs: 300000, // 5 minutes
  nonceHeader: 'X-Request-Nonce',
  timestampHeader: 'X-Request-Timestamp',
  maxTimeDrift: 60000, // 1 minute
  skipMethods: ['GET', 'HEAD', 'OPTIONS'],
};

// =============================================================================
// Nonce Store Interface
// =============================================================================

/**
 * Interface for nonce storage backends.
 * Allows swapping between in-memory, Redis, and database implementations.
 */
export interface INonceStore {
  checkAndAdd(
    nonce: string,
    timestamp: number,
    metadata?: { clientIp?: string; path?: string; tenantId?: string }
  ): boolean | Promise<boolean>;
  exists(nonce: string, timestamp: number, tenantId?: string): boolean | Promise<boolean>;
  cleanup(): number | Promise<number>;
  readonly size: number;
  destroy(): void | Promise<void>;
}

// =============================================================================
// In-Memory Nonce Store
// =============================================================================

/** Default maximum number of nonces to hold in memory */
const DEFAULT_MAX_NONCES = 100_000;
/** Warn when nonce store reaches this fraction of capacity */
const NONCE_PRESSURE_THRESHOLD = 0.8;

/**
 * In-memory store for tracking used nonces.
 *
 * PEN-006: For production with multiple instances, use RedisNonceStore or PrismaNonceStore instead.
 * This implementation is suitable for single-instance deployments or development.
 *
 * Memory safety: The store enforces a hard capacity limit (maxNonces). When capacity
 * is reached, expired nonces are evicted first. If still at capacity, the oldest
 * entries are evicted to make room. This prevents unbounded memory growth during
 * sustained traffic spikes or DoS conditions.
 */
export class NonceStore implements INonceStore {
  private nonces: Map<string, NonceMetadata> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private windowMs: number;
  private maxNonces: number;
  /** Callback for capacity-related events (evictions, pressure warnings) */
  private onCapacityEvent?: (event: 'pressure' | 'eviction' | 'at_capacity', detail: { size: number; maxNonces: number; evicted?: number }) => void;

  /**
   * Create a new nonce store.
   *
   * @param windowMs - Time window for nonce validity (default: 5 minutes)
   * @param cleanupIntervalMs - Interval for cleanup of expired nonces (default: 60s)
   * @param maxNonces - Maximum nonces to hold in memory (default: 100,000)
   * @param onCapacityEvent - Optional callback for capacity events (monitoring integration)
   */
  constructor(
    windowMs: number = 300000,
    cleanupIntervalMs: number = 60000,
    maxNonces: number = DEFAULT_MAX_NONCES,
    onCapacityEvent?: (event: 'pressure' | 'eviction' | 'at_capacity', detail: { size: number; maxNonces: number; evicted?: number }) => void,
  ) {
    this.windowMs = windowMs;
    this.maxNonces = maxNonces;
    this.onCapacityEvent = onCapacityEvent;
    this.startCleanup(cleanupIntervalMs);
  }

  /**
   * Check if a nonce exists and add it if not.
   *
   * When the store is at capacity, expired entries are evicted first. If still
   * at capacity after eviction, the oldest entries are removed to make room.
   *
   * @param nonce - The nonce to check
   * @param timestamp - Request timestamp
   * @param metadata - Optional metadata for logging
   * @returns true if nonce is new (valid), false if reused
   */
  checkAndAdd(
    nonce: string,
    timestamp: number,
    metadata?: { clientIp?: string; path?: string; tenantId?: string }
  ): boolean {
    // Create composite key with timestamp and optional tenantId to handle clock skew and multi-tenancy
    const tenantPart = metadata?.tenantId ? `${metadata.tenantId}:` : '';
    const key = `${tenantPart}${nonce}:${Math.floor(timestamp / 1000)}`;

    if (this.nonces.has(key)) {
      return false; // Nonce already used
    }

    // Enforce capacity limit before inserting
    if (this.nonces.size >= this.maxNonces) {
      this.enforceCapacity();
    }

    this.nonces.set(key, {
      timestamp,
      expiresAt: Date.now() + this.windowMs,
      clientIp: metadata?.clientIp,
      path: metadata?.path,
    });

    // Emit pressure warning when approaching capacity
    if (this.nonces.size >= this.maxNonces * NONCE_PRESSURE_THRESHOLD) {
      this.onCapacityEvent?.('pressure', { size: this.nonces.size, maxNonces: this.maxNonces });
    }

    return true;
  }

  /**
   * Check if a nonce exists without adding it.
   *
   * @param nonce - The nonce to check
   * @param timestamp - Request timestamp
   * @param tenantId - Optional tenant identifier
   * @returns true if nonce exists (was already used)
   */
  exists(nonce: string, timestamp: number, tenantId?: string): boolean {
    const tenantPart = tenantId ? `${tenantId}:` : '';
    const key = `${tenantPart}${nonce}:${Math.floor(timestamp / 1000)}`;
    return this.nonces.has(key);
  }

  /**
   * Manually trigger cleanup of expired nonces.
   *
   * @returns Number of nonces removed
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, metadata] of this.nonces.entries()) {
      if (metadata.expiresAt < now) {
        this.nonces.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get the number of tracked nonces.
   */
  get size(): number {
    return this.nonces.size;
  }

  /**
   * Get the configured capacity limit.
   */
  get capacity(): number {
    return this.maxNonces;
  }

  /**
   * Clear all nonces and stop cleanup.
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.nonces.clear();
  }

  /**
   * Enforce capacity limits when the store is full.
   *
   * Strategy:
   * 1. Evict all expired entries (TTL-based cleanup)
   * 2. If still at capacity, evict oldest 10% of entries
   *
   * This ensures the store never exceeds maxNonces while preserving
   * the most recent nonces for replay detection.
   */
  private enforceCapacity(): void {
    // Step 1: Try TTL-based eviction first
    const expired = this.cleanup();

    if (this.nonces.size < this.maxNonces) {
      if (expired > 0) {
        this.onCapacityEvent?.('eviction', { size: this.nonces.size, maxNonces: this.maxNonces, evicted: expired });
      }
      return;
    }

    // Step 2: Still at capacity - evict oldest 10% of entries
    const evictCount = Math.max(1, Math.ceil(this.maxNonces * 0.1));
    let evicted = 0;
    for (const key of this.nonces.keys()) {
      if (evicted >= evictCount) break;
      this.nonces.delete(key);
      evicted++;
    }

    this.onCapacityEvent?.('at_capacity', {
      size: this.nonces.size,
      maxNonces: this.maxNonces,
      evicted: expired + evicted,
    });
  }

  /**
   * Start periodic cleanup.
   */
  private startCleanup(intervalMs: number): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, intervalMs);

    // Don't prevent process from exiting
    this.cleanupInterval.unref();
  }
}

// =============================================================================
// Redis Nonce Store (PEN-006)
// =============================================================================

/**
 * Redis client interface - compatible with ioredis.
 * Import your Redis client and pass it to RedisNonceStore.
 */
export interface RedisClient {
  set(key: string, value: string, mode: 'EX', ttl: number, flag: 'NX'): Promise<'OK' | null>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  quit(): Promise<'OK'>;
}

/**
 * Redis-backed nonce store for distributed deployments.
 *
 * PEN-006: Prevents replay attacks across multiple application instances
 * by using Redis as a shared nonce store with automatic TTL expiration.
 *
 * @example
 * ```typescript
 * import Redis from 'ioredis';
 *
 * const redis = new Redis(process.env.REDIS_URL);
 * const store = new RedisNonceStore(redis, {
 *   windowMs: 300000,  // 5 minutes
 *   keyPrefix: 'replay:nonce:',
 * });
 *
 * const { middleware } = createReplayProtection({
 *   windowMs: 300000,
 *   store,  // Use Redis store instead of in-memory
 * });
 * ```
 */
export class RedisNonceStore implements INonceStore {
  private redis: RedisClient;
  private windowMs: number;
  private keyPrefix: string;
  private _size: number = 0;

  constructor(
    redis: RedisClient,
    options: {
      windowMs?: number;
      keyPrefix?: string;
    } = {}
  ) {
    this.redis = redis;
    this.windowMs = options.windowMs ?? 300000;
    this.keyPrefix = options.keyPrefix ?? 'replay:nonce:';
  }

  /**
   * Check if a nonce exists and add it if not (atomic operation).
   * Uses Redis SET NX with TTL for atomic check-and-set.
   */
  async checkAndAdd(
    nonce: string,
    timestamp: number,
    metadata?: { clientIp?: string; path?: string }
  ): Promise<boolean> {
    const key = `${this.keyPrefix}${nonce}:${Math.floor(timestamp / 1000)}`;
    const ttlSeconds = Math.ceil(this.windowMs / 1000);

    // Store metadata as JSON
    const value = JSON.stringify({
      timestamp,
      clientIp: metadata?.clientIp,
      path: metadata?.path,
      createdAt: Date.now(),
    });

    // SET NX returns 'OK' if key was set, null if key already exists
    const result = await this.redis.set(key, value, 'EX', ttlSeconds, 'NX');

    if (result === 'OK') {
      this._size++;
      return true; // Nonce is new
    }

    return false; // Nonce already used
  }

  /**
   * Check if a nonce exists without adding it.
   */
  async exists(nonce: string, timestamp: number): Promise<boolean> {
    const key = `${this.keyPrefix}${nonce}:${Math.floor(timestamp / 1000)}`;
    const result = await this.redis.get(key);
    return result !== null;
  }

  /**
   * Redis handles cleanup via TTL, but this can be called for manual cleanup.
   * Returns approximate count of keys (not exact due to distributed nature).
   */
  async cleanup(): Promise<number> {
    // Redis handles TTL-based expiration automatically
    // This method is a no-op for Redis, included for interface compatibility
    return 0;
  }

  /**
   * Get approximate size (may not be accurate in distributed setting).
   */
  get size(): number {
    return this._size;
  }

  /**
   * Close Redis connection.
   */
  async destroy(): Promise<void> {
    await this.redis.quit();
  }
}

// =============================================================================
// Prisma Nonce Store (Distributed DB-backed)
// =============================================================================

/**
 * Prisma-backed nonce store for distributed deployments without Redis.
 *
 * Uses the existing `IdempotencyRequest` table to track used nonces/keys.
 * This ensures cross-instance deduplication using the primary database.
 */
export class PrismaNonceStore implements INonceStore {
  private prisma: PrismaClient;
  private windowMs: number;
  private _size: number = 0;

  constructor(
    prisma: PrismaClient,
    options: {
      windowMs?: number;
    } = {}
  ) {
    this.prisma = prisma;
    this.windowMs = options.windowMs ?? 300000;
  }

  /**
   * Check if a nonce exists and add it if not.
   * Uses the IdempotencyRequest table with tenantId scoped uniqueness.
   */
  async checkAndAdd(
    nonce: string,
    timestamp: number,
    metadata?: { clientIp?: string; path?: string; tenantId?: string }
  ): Promise<boolean> {
    // IdempotencyRequest model requires a tenantId. 
    // If not provided, we can't use this table (as it's part of the PK).
    if (!metadata?.tenantId) {
      throw new Error('PrismaNonceStore requires a tenantId in metadata');
    }

    const tenantId = metadata.tenantId;
    const expiresAt = new Date(Date.now() + this.windowMs);

    try {
      // Attempt to create the idempotency record. 
      // If it already exists, Prisma will throw a unique constraint error (P2002).
      await this.prisma.idempotencyRequest.create({
        data: {
          key: nonce,
          tenantId,
          response: { 
            status: 'accepted',
            timestamp,
            clientIp: metadata.clientIp,
            path: metadata.path
          } as any, // Cast to any for Prisma JSON compatibility
          expiresAt,
        },
      });

      this._size++;
      return true;
    } catch (error: any) {
      // P2002 is Unique constraint failed
      if (error.code === 'P2002') {
        return false;
      }
      throw error;
    }
  }

  /**
   * Check if a nonce exists without adding it.
   */
  async exists(nonce: string, _timestamp: number, tenantId?: string): Promise<boolean> {
    if (!tenantId) return false;

    const entry = await this.prisma.idempotencyRequest.findUnique({
      where: {
        key_tenantId: { key: nonce, tenantId },
      },
    });

    return !!entry;
  }

  /**
   * Remove expired nonces from the database.
   */
  async cleanup(): Promise<number> {
    const result = await this.prisma.idempotencyRequest.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });
    return result.count;
  }

  /**
   * Get approximate size (last known created count).
   */
  get size(): number {
    return this._size;
  }

  /**
   * No-op for Prisma store.
   */
  async destroy(): Promise<void> {
    // No connection to close
  }
}

// =============================================================================
// Validation Functions
// =============================================================================

/**
 * Validate a timestamp against the allowed window.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @param maxDrift - Maximum allowed clock drift
 * @param windowMs - Time window for validity
 * @returns Error code if invalid, null if valid
 */
export function validateTimestamp(
  timestamp: number,
  maxDrift: number,
  windowMs: number
): ReplayProtectionError | null {
  const now = Date.now();

  // Check if timestamp is too far in the future
  if (timestamp > now + maxDrift) {
    return 'timestamp_future';
  }

  // Check if timestamp is too old
  if (timestamp < now - windowMs) {
    return 'timestamp_expired';
  }

  return null;
}

/**
 * Validate nonce format.
 *
 * Nonces must be:
 * - At least 16 characters
 * - Only contain alphanumeric characters and hyphens
 * - Not exceed 64 characters
 *
 * @param nonce - The nonce to validate
 * @returns true if format is valid
 */
export function validateNonceFormat(nonce: string): boolean {
  if (!nonce || typeof nonce !== 'string') {
    return false;
  }

  if (nonce.length < 16 || nonce.length > 64) {
    return false;
  }

  // Allow alphanumeric and hyphens
  return /^[a-zA-Z0-9-]+$/.test(nonce);
}

/**
 * Generate a cryptographically secure nonce.
 *
 * @param length - Number of random bytes (default: 16, resulting in 32 hex chars)
 * @returns Hex-encoded nonce string
 */
export function generateNonce(length: number = 16): string {
  return randomBytes(length).toString('hex');
}

// =============================================================================
// Middleware Factory
// =============================================================================

/**
 * Extended configuration with optional external store.
 */
export interface ReplayProtectionFactoryConfig extends Partial<ReplayProtectionConfig> {
  /**
   * External nonce store (e.g., RedisNonceStore for distributed deployments).
   * If not provided, uses in-memory NonceStore.
   */
  store?: INonceStore;
  /**
   * Maximum nonces to hold in the in-memory store (default: 100,000).
   * Only applies when no external store is provided.
   */
  maxNonces?: number;
}

/**
 * Create replay protection middleware.
 *
 * PEN-006: Supports both in-memory and Redis-backed nonce stores
 * for single-instance and distributed deployments.
 *
 * @example
 * ```typescript
 * // Single instance (in-memory)
 * const { middleware, store, destroy } = createReplayProtection({
 *   windowMs: 300000,
 *   skipRoutes: ['/health', '/metrics'],
 *   skipMethods: ['GET', 'HEAD', 'OPTIONS'],
 * });
 *
 * // Distributed deployment (Redis)
 * import Redis from 'ioredis';
 * const redis = new Redis(process.env.REDIS_URL);
 * const redisStore = new RedisNonceStore(redis, { windowMs: 300000 });
 *
 * const { middleware, store, destroy } = createReplayProtection({
 *   windowMs: 300000,
 *   store: redisStore,  // Use Redis for distributed nonce tracking
 * });
 *
 * app.use('/api', middleware);
 *
 * // On shutdown
 * await destroy();
 * ```
 */
export function createReplayProtection(
  config: ReplayProtectionFactoryConfig = {}
): {
  middleware: RequestHandler;
  store: INonceStore;
  destroy: () => void | Promise<void>;
} {
  const fullConfig = { ...DEFAULT_REPLAY_CONFIG, ...config };
  const store = config.store ?? new NonceStore(
    fullConfig.windowMs,
    undefined,
    config.maxNonces,
  );

  const middleware: RequestHandler = (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    // Skip certain methods
    if (fullConfig.skipMethods?.includes(req.method)) {
      next();
      return;
    }

    // Skip certain routes
    if (fullConfig.skipRoutes) {
      for (const route of fullConfig.skipRoutes) {
        if (typeof route === 'string' && req.path === route) {
          next();
          return;
        }
        if (route instanceof RegExp && route.test(req.path)) {
          next();
          return;
        }
      }
    }

    // Get nonce header
    const nonce = req.headers[fullConfig.nonceHeader.toLowerCase()] as string;
    if (!nonce) {
      res.status(400).json({
        error: 'Bad Request',
        code: 'missing_nonce',
        message: `Missing required header: ${fullConfig.nonceHeader}`,
      });
      return;
    }

    // Validate nonce format
    if (!validateNonceFormat(nonce)) {
      res.status(400).json({
        error: 'Bad Request',
        code: 'invalid_nonce_format',
        message: 'Nonce must be 16-64 alphanumeric characters',
      });
      return;
    }

    // Get timestamp header
    const timestampStr = req.headers[
      fullConfig.timestampHeader.toLowerCase()
    ] as string;
    if (!timestampStr) {
      res.status(400).json({
        error: 'Bad Request',
        code: 'missing_timestamp',
        message: `Missing required header: ${fullConfig.timestampHeader}`,
      });
      return;
    }

    // Parse timestamp
    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      res.status(400).json({
        error: 'Bad Request',
        code: 'invalid_timestamp_format',
        message: 'Timestamp must be a Unix timestamp in milliseconds',
      });
      return;
    }

    // Validate timestamp
    const timestampError = validateTimestamp(
      timestamp,
      fullConfig.maxTimeDrift,
      fullConfig.windowMs
    );
    if (timestampError) {
      const message =
        timestampError === 'timestamp_future'
          ? 'Timestamp is too far in the future'
          : 'Timestamp has expired';
      res.status(400).json({
        error: 'Bad Request',
        code: timestampError,
        message,
      });
      return;
    }

    // Check and add nonce (supports both sync and async stores)
    const clientIp = getClientIp(req);
    const checkResult = store.checkAndAdd(nonce, timestamp, {
      clientIp,
      path: req.path,
    });

    // Handle both sync (in-memory) and async (Redis) stores
    const handleResult = (isNew: boolean) => {
      if (!isNew) {
        res.status(409).json({
          error: 'Conflict',
          code: 'nonce_reused',
          message: 'Request nonce has already been used',
        });
        return;
      }
      next();
    };

    if (checkResult instanceof Promise) {
      checkResult
        .then(handleResult)
        .catch((error) => {
          // Log error but allow request to proceed (fail-open for availability)
          // In high-security contexts, you may want to fail-closed instead
          console.error('Replay protection store error:', error);
          next();
        });
    } else {
      handleResult(checkResult);
    }
  };

  return {
    middleware,
    store,
    destroy: () => store.destroy(),
  };
}

/**
 * Extract client IP from request.
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

// =============================================================================
// Validation Function for Direct Use
// =============================================================================

/**
 * Validate replay protection headers without middleware.
 *
 * Useful for WebSocket or non-Express contexts.
 * PEN-006: Supports both sync and async nonce stores.
 *
 * @param nonce - Request nonce
 * @param timestamp - Request timestamp (ms)
 * @param store - Nonce store instance (INonceStore)
 * @param config - Configuration options
 * @returns Validation result (Promise for async stores)
 */
export async function validateReplayProtection(
  nonce: string | undefined,
  timestamp: number | undefined,
  store: INonceStore,
  config: Pick<ReplayProtectionConfig, 'windowMs' | 'maxTimeDrift'> = {
    windowMs: DEFAULT_REPLAY_CONFIG.windowMs,
    maxTimeDrift: DEFAULT_REPLAY_CONFIG.maxTimeDrift,
  }
): Promise<ReplayProtectionResult> {
  // Check nonce
  if (!nonce) {
    return {
      valid: false,
      error: 'missing_nonce',
      message: 'Request nonce is required',
    };
  }

  if (!validateNonceFormat(nonce)) {
    return {
      valid: false,
      error: 'invalid_nonce_format',
      message: 'Nonce must be 16-64 alphanumeric characters',
    };
  }

  // Check timestamp
  if (timestamp === undefined || timestamp === null) {
    return {
      valid: false,
      error: 'missing_timestamp',
      message: 'Request timestamp is required',
    };
  }

  if (typeof timestamp !== 'number' || isNaN(timestamp)) {
    return {
      valid: false,
      error: 'invalid_timestamp_format',
      message: 'Timestamp must be a valid number',
    };
  }

  const timestampError = validateTimestamp(
    timestamp,
    config.maxTimeDrift,
    config.windowMs
  );
  if (timestampError) {
    return {
      valid: false,
      error: timestampError,
      message:
        timestampError === 'timestamp_future'
          ? 'Timestamp is too far in the future'
          : 'Timestamp has expired',
    };
  }

  // Check nonce reuse (await for async stores)
  const isNew = await store.checkAndAdd(nonce, timestamp);
  if (!isNew) {
    return {
      valid: false,
      error: 'nonce_reused',
      message: 'Request nonce has already been used',
    };
  }

  return { valid: true };
}
