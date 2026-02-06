/**
 * WebSocket Rate Limiter
 *
 * Token bucket algorithm for WebSocket message flooding protection.
 * Prevents denial of service through message spam while allowing
 * legitimate burst traffic.
 *
 * @module ws-rate-limiter
 */

// =============================================================================
// Types
// =============================================================================

/**
 * Configuration for WebSocket rate limiting.
 */
export interface RateLimitConfig {
  /** Maximum messages allowed per second (refill rate) */
  maxMessagesPerSecond: number;
  /** Maximum burst size (bucket capacity) */
  burstLimit: number;
  /** Whether to disconnect on limit exceeded */
  disconnectOnExceed: boolean;
  /** Cleanup interval for stale connections (ms) */
  cleanupIntervalMs?: number;
  /** Time after which a connection is considered stale (ms) */
  staleConnectionMs?: number;
}

/**
 * Result of a rate limit check.
 */
export interface RateLimitResult {
  /** Whether the message is allowed */
  allowed: boolean;
  /** Number of tokens remaining */
  remaining: number;
  /** Whether the connection should be disconnected */
  shouldDisconnect: boolean;
  /** Time until next token is available (ms) */
  retryAfterMs: number;
}

/**
 * Token bucket state for a connection.
 */
interface TokenBucket {
  /** Current number of tokens */
  tokens: number;
  /** Last time tokens were added */
  lastRefill: number;
  /** Number of times limit was exceeded */
  violations: number;
  /** Last activity timestamp */
  lastActivity: number;
}

/**
 * Statistics about rate limiter state.
 */
export interface RateLimiterStats {
  /** Number of active connections being tracked */
  activeConnections: number;
  /** Total number of limit violations */
  totalLimitViolations: number;
  /** Current configuration */
  config: RateLimitConfig;
}

// =============================================================================
// Default Configuration
// =============================================================================

/**
 * Default rate limit configuration.
 */
export const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = {
  maxMessagesPerSecond: 100,
  burstLimit: 150,
  disconnectOnExceed: true,
  cleanupIntervalMs: 60000,
  staleConnectionMs: 300000,
};

// =============================================================================
// WebSocket Rate Limiter Class
// =============================================================================

/**
 * Token bucket rate limiter for WebSocket connections.
 *
 * Implements the token bucket algorithm:
 * - Each connection has a bucket with a maximum capacity (burstLimit)
 * - Tokens are added at a constant rate (maxMessagesPerSecond)
 * - Each message consumes one token
 * - If no tokens are available, the message is rejected
 *
 * @example
 * ```typescript
 * const limiter = new WebSocketRateLimiter({
 *   maxMessagesPerSecond: 100,
 *   burstLimit: 150,
 *   disconnectOnExceed: true,
 * });
 *
 * ws.on('message', (data) => {
 *   const result = limiter.checkLimit(connectionId);
 *   if (!result.allowed) {
 *     if (result.shouldDisconnect) {
 *       ws.close(1008, 'Rate limit exceeded');
 *     }
 *     return;
 *   }
 *   // Process message
 * });
 *
 * ws.on('close', () => {
 *   limiter.removeConnection(connectionId);
 * });
 * ```
 */
export class WebSocketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private config: RateLimitConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private totalViolations = 0;

  /**
   * Create a new WebSocket rate limiter.
   *
   * @param config - Rate limit configuration
   */
  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMIT_CONFIG, ...config };
    this.startCleanup();
  }

  /**
   * Check if a message from a connection is allowed.
   *
   * This consumes a token if available. Use peekLimit() to check
   * without consuming a token.
   *
   * @param connectionId - Unique identifier for the connection
   * @returns Rate limit result
   */
  checkLimit(connectionId: string): RateLimitResult {
    const now = Date.now();
    let bucket = this.buckets.get(connectionId);

    // Initialize bucket for new connections
    if (!bucket) {
      bucket = {
        tokens: this.config.burstLimit,
        lastRefill: now,
        violations: 0,
        lastActivity: now,
      };
      this.buckets.set(connectionId, bucket);
    }

    // Refill tokens based on elapsed time
    this.refillTokens(bucket, now);
    bucket.lastActivity = now;

    // Check if we have tokens available
    if (bucket.tokens >= 1) {
      bucket.tokens--;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        shouldDisconnect: false,
        retryAfterMs: 0,
      };
    }

    // Rate limit exceeded
    bucket.violations++;
    this.totalViolations++;

    // Calculate time until next token
    const msPerToken = 1000 / this.config.maxMessagesPerSecond;
    const retryAfterMs = Math.ceil(msPerToken);

    return {
      allowed: false,
      remaining: 0,
      shouldDisconnect: this.config.disconnectOnExceed,
      retryAfterMs,
    };
  }

  /**
   * Check rate limit status without consuming a token.
   *
   * Useful for UI feedback before sending messages.
   *
   * @param connectionId - Unique identifier for the connection
   * @returns Rate limit result (allowed reflects current state)
   */
  peekLimit(connectionId: string): RateLimitResult {
    const now = Date.now();
    const bucket = this.buckets.get(connectionId);

    if (!bucket) {
      // New connection would have full bucket
      return {
        allowed: true,
        remaining: this.config.burstLimit,
        shouldDisconnect: false,
        retryAfterMs: 0,
      };
    }

    // Calculate current tokens without modifying state
    const elapsedMs = now - bucket.lastRefill;
    const tokensToAdd = (elapsedMs / 1000) * this.config.maxMessagesPerSecond;
    const currentTokens = Math.min(
      this.config.burstLimit,
      bucket.tokens + tokensToAdd
    );

    if (currentTokens >= 1) {
      return {
        allowed: true,
        remaining: Math.floor(currentTokens),
        shouldDisconnect: false,
        retryAfterMs: 0,
      };
    }

    const msPerToken = 1000 / this.config.maxMessagesPerSecond;
    const tokensNeeded = 1 - currentTokens;
    const retryAfterMs = Math.ceil(tokensNeeded * msPerToken);

    return {
      allowed: false,
      remaining: 0,
      shouldDisconnect: this.config.disconnectOnExceed,
      retryAfterMs,
    };
  }

  /**
   * Remove a connection from tracking.
   *
   * Call this when a WebSocket connection closes.
   *
   * @param connectionId - Unique identifier for the connection
   */
  removeConnection(connectionId: string): void {
    this.buckets.delete(connectionId);
  }

  /**
   * Reset rate limiting for a connection.
   *
   * Restores full token bucket. Use sparingly.
   *
   * @param connectionId - Unique identifier for the connection
   */
  resetConnection(connectionId: string): void {
    const bucket = this.buckets.get(connectionId);
    if (bucket) {
      bucket.tokens = this.config.burstLimit;
      bucket.lastRefill = Date.now();
      bucket.violations = 0;
    }
  }

  /**
   * Get statistics about the rate limiter.
   *
   * @returns Current limiter statistics
   */
  getStats(): RateLimiterStats {
    return {
      activeConnections: this.buckets.size,
      totalLimitViolations: this.totalViolations,
      config: { ...this.config },
    };
  }

  /**
   * Get violation count for a specific connection.
   *
   * @param connectionId - Unique identifier for the connection
   * @returns Number of violations, or 0 if connection not tracked
   */
  getConnectionViolations(connectionId: string): number {
    return this.buckets.get(connectionId)?.violations ?? 0;
  }

  /**
   * Cleanup and stop the rate limiter.
   *
   * Call this when shutting down the WebSocket server.
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.buckets.clear();
  }

  /**
   * Refill tokens based on elapsed time since last refill.
   */
  private refillTokens(bucket: TokenBucket, now: number): void {
    const elapsedMs = now - bucket.lastRefill;
    const tokensToAdd = (elapsedMs / 1000) * this.config.maxMessagesPerSecond;

    if (tokensToAdd > 0) {
      bucket.tokens = Math.min(
        this.config.burstLimit,
        bucket.tokens + tokensToAdd
      );
      bucket.lastRefill = now;
    }
  }

  /**
   * Start periodic cleanup of stale connections.
   */
  private startCleanup(): void {
    const cleanupMs = this.config.cleanupIntervalMs ?? 60000;
    const staleMs = this.config.staleConnectionMs ?? 300000;

    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [connectionId, bucket] of this.buckets.entries()) {
        if (now - bucket.lastActivity > staleMs) {
          this.buckets.delete(connectionId);
        }
      }
    }, cleanupMs);

    // Don't prevent process from exiting
    this.cleanupInterval.unref();
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

/**
 * Default WebSocket rate limiter instance.
 *
 * Use this for simple applications. Create custom instances
 * with different configs for more control.
 */
export const defaultWsRateLimiter = new WebSocketRateLimiter();
