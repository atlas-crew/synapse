/**
 * Log Streamer for Signal Horizon
 *
 * Manages log subscriptions from dashboard clients to sensor log streams.
 * Routes log entries from sensors to subscribed clients with filtering,
 * rate limiting, and subscription lifecycle management.
 *
 * @module log-streamer
 */

import { EventEmitter } from 'node:events';
import type { Logger } from 'pino';
import type { WebSocket } from 'ws';
import type {
  LogSource,
  LogLevel,
  LogFilter,
  LogEntryMessage,
} from '../types/tunnel.js';
import { createSafeRegex, testRegexWithTimeout } from '../lib/regex-validator.js';

// =============================================================================
// Types
// =============================================================================

/**
 * Log subscription representing a client's interest in log streams.
 */
interface LogSubscription {
  /** Unique subscription identifier */
  id: string;
  /** Sensor ID being subscribed to */
  sensorId: string;
  /** Log sources to receive */
  sources: LogSource[];
  /** Optional filter criteria */
  filter?: LogFilter;
  /** Client WebSocket connection */
  ws: WebSocket;
  /** Subscription creation timestamp */
  createdAt: Date;
  /** Total log entries received */
  entriesReceived: number;
  /** Entries forwarded to client */
  entriesForwarded: number;
  /** Entries filtered out */
  entriesFiltered: number;
  /** Rate limit: max entries per second */
  rateLimit: number;
  /** Rate limiting state */
  rateLimitState: {
    /** Token bucket tokens */
    tokens: number;
    /** Last refill timestamp */
    lastRefill: number;
  };
}

/**
 * Log subscription statistics for a sensor.
 */
interface SensorLogStats {
  /** Total subscriptions for this sensor */
  subscriptionCount: number;
  /** Total entries routed to clients */
  entriesRouted: number;
  /** Entries dropped due to rate limiting */
  entriesDropped: number;
  /** Entries filtered out */
  entriesFiltered: number;
}

/**
 * Events emitted by the LogStreamer.
 */
export interface LogStreamerEvents {
  /** New subscription created */
  'subscription-created': (subscriptionId: string, sensorId: string, sources: LogSource[]) => void;
  /** Subscription removed */
  'subscription-removed': (subscriptionId: string, reason: string) => void;
  /** Log entry routed to client */
  'entry-routed': (subscriptionId: string, sensorId: string, level: LogLevel) => void;
  /** Entry dropped due to rate limiting */
  'entry-rate-limited': (subscriptionId: string, sensorId: string) => void;
  /** Entry filtered out */
  'entry-filtered': (subscriptionId: string, sensorId: string, reason: string) => void;
  /** Error during log routing */
  'routing-error': (subscriptionId: string, error: Error) => void;
}

/**
 * Default rate limit: 1000 entries per second per subscription.
 */
const DEFAULT_RATE_LIMIT = 1000;

/**
 * Log level severity ordering for filtering.
 */
const LOG_LEVEL_SEVERITY: Record<LogLevel, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  fatal: 5,
};

// =============================================================================
// LogStreamer Class
// =============================================================================

/**
 * Manages log subscriptions and routes log entries from sensors to clients.
 *
 * LogStreamer provides:
 * - Subscription lifecycle management (create, remove, cleanup)
 * - Log filtering by source, level, and pattern
 * - Per-subscription rate limiting (token bucket)
 * - Statistics tracking for monitoring
 *
 * @example
 * ```typescript
 * const streamer = new LogStreamer(logger);
 *
 * // Client subscribes to sensor logs
 * streamer.subscribe('sub-123', 'sensor-001', ['access', 'error'], {
 *   minLevel: 'warn',
 *   pattern: 'timeout',
 * }, clientWs);
 *
 * // Route log entry from sensor to subscribed clients
 * streamer.routeLogEntry('sensor-001', logEntry);
 *
 * // Client unsubscribes
 * streamer.unsubscribe('sub-123');
 *
 * // Cleanup when sensor disconnects
 * streamer.cleanupSensor('sensor-001');
 * ```
 */
export class LogStreamer extends EventEmitter {
  /** Active subscriptions by ID */
  private subscriptions: Map<string, LogSubscription> = new Map();

  /** Subscription IDs grouped by sensor ID */
  private sensorSubscriptions: Map<string, Set<string>> = new Map();

  /** Per-sensor statistics */
  private sensorStats: Map<string, SensorLogStats> = new Map();

  /** Logger instance */
  private logger: Logger;

  /** Rate limit refill interval (ms) */
  private readonly RATE_LIMIT_REFILL_MS = 1000;

  constructor(logger: Logger) {
    super();
    this.logger = logger.child({ component: 'log-streamer' });
    this.logger.info('LogStreamer initialized');
  }

  // ===========================================================================
  // Subscription Management
  // ===========================================================================

  /**
   * Create a new log subscription for a client.
   *
   * @param subscriptionId - Unique subscription identifier
   * @param sensorId - Sensor ID to subscribe to
   * @param sources - Log sources to receive (empty = all)
   * @param filter - Optional filter criteria
   * @param ws - Client WebSocket connection
   * @param rateLimit - Max entries per second (default: 1000)
   */
  subscribe(
    subscriptionId: string,
    sensorId: string,
    sources: LogSource[],
    filter: LogFilter | undefined,
    ws: WebSocket,
    rateLimit: number = DEFAULT_RATE_LIMIT
  ): void {
    // Check if subscription already exists
    if (this.subscriptions.has(subscriptionId)) {
      this.logger.warn({ subscriptionId }, 'Subscription already exists, replacing');
      this.unsubscribe(subscriptionId);
    }

    // Create subscription
    const subscription: LogSubscription = {
      id: subscriptionId,
      sensorId,
      sources,
      filter,
      ws,
      createdAt: new Date(),
      entriesReceived: 0,
      entriesForwarded: 0,
      entriesFiltered: 0,
      rateLimit,
      rateLimitState: {
        tokens: rateLimit,
        lastRefill: Date.now(),
      },
    };

    this.subscriptions.set(subscriptionId, subscription);

    // Track by sensor
    if (!this.sensorSubscriptions.has(sensorId)) {
      this.sensorSubscriptions.set(sensorId, new Set());
    }
    this.sensorSubscriptions.get(sensorId)!.add(subscriptionId);

    // Initialize sensor stats if needed
    if (!this.sensorStats.has(sensorId)) {
      this.sensorStats.set(sensorId, {
        subscriptionCount: 0,
        entriesRouted: 0,
        entriesDropped: 0,
        entriesFiltered: 0,
      });
    }
    this.sensorStats.get(sensorId)!.subscriptionCount++;

    // Set up WebSocket close handler
    ws.on('close', () => {
      this.unsubscribe(subscriptionId);
    });

    ws.on('error', (error) => {
      this.logger.error({ error, subscriptionId }, 'Client WebSocket error');
      this.unsubscribe(subscriptionId);
    });

    this.emit('subscription-created', subscriptionId, sensorId, sources);
    this.logger.info(
      { subscriptionId, sensorId, sources, filter, rateLimit },
      'Log subscription created'
    );
  }

  /**
   * Remove a subscription.
   *
   * @param subscriptionId - Subscription ID to remove
   */
  unsubscribe(subscriptionId: string): void {
    const subscription = this.subscriptions.get(subscriptionId);
    if (!subscription) {
      return;
    }

    // Remove from sensor tracking
    const sensorSubs = this.sensorSubscriptions.get(subscription.sensorId);
    if (sensorSubs) {
      sensorSubs.delete(subscriptionId);
      if (sensorSubs.size === 0) {
        this.sensorSubscriptions.delete(subscription.sensorId);
      }
    }

    // Update sensor stats
    const stats = this.sensorStats.get(subscription.sensorId);
    if (stats) {
      stats.subscriptionCount--;
      if (stats.subscriptionCount === 0) {
        this.sensorStats.delete(subscription.sensorId);
      }
    }

    // Remove subscription
    this.subscriptions.delete(subscriptionId);

    this.emit('subscription-removed', subscriptionId, 'unsubscribed');
    this.logger.info(
      {
        subscriptionId,
        sensorId: subscription.sensorId,
        entriesForwarded: subscription.entriesForwarded,
        entriesFiltered: subscription.entriesFiltered,
      },
      'Log subscription removed'
    );
  }

  // ===========================================================================
  // Log Routing
  // ===========================================================================

  /**
   * Route a log entry from a sensor to all subscribed clients.
   *
   * Applies filtering, rate limiting, and forwards matching entries
   * to each subscription's WebSocket connection.
   *
   * @param sensorId - Sensor ID the entry came from
   * @param entry - Log entry message to route
   */
  routeLogEntry(sensorId: string, entry: LogEntryMessage): void {
    const subscriptionIds = this.sensorSubscriptions.get(sensorId);
    if (!subscriptionIds || subscriptionIds.size === 0) {
      // No subscribers for this sensor
      return;
    }

    for (const subscriptionId of subscriptionIds) {
      const subscription = this.subscriptions.get(subscriptionId);
      if (!subscription) {
        continue;
      }

      subscription.entriesReceived++;

      // Check if entry passes filter
      const filterResult = this.passesFilter(subscription, entry);
      if (!filterResult.passes) {
        subscription.entriesFiltered++;
        const stats = this.sensorStats.get(sensorId);
        if (stats) {
          stats.entriesFiltered++;
        }
        this.emit('entry-filtered', subscriptionId, sensorId, filterResult.reason ?? 'unknown');
        continue;
      }

      // Check rate limit
      if (!this.checkRateLimit(subscription)) {
        const stats = this.sensorStats.get(sensorId);
        if (stats) {
          stats.entriesDropped++;
        }
        this.emit('entry-rate-limited', subscriptionId, sensorId);
        continue;
      }

      // Forward entry to client
      try {
        if (subscription.ws.readyState === 1) {
          // WebSocket.OPEN
          subscription.ws.send(JSON.stringify(entry));
          subscription.entriesForwarded++;
          const stats = this.sensorStats.get(sensorId);
          if (stats) {
            stats.entriesRouted++;
          }
          this.emit('entry-routed', subscriptionId, sensorId, entry.level);
        }
      } catch (error) {
        this.logger.error({ error, subscriptionId, sensorId }, 'Failed to send log entry');
        this.emit('routing-error', subscriptionId, error as Error);
      }
    }
  }

  /**
   * Check if a log entry passes the subscription's filter criteria.
   */
  private passesFilter(
    subscription: LogSubscription,
    entry: LogEntryMessage
  ): { passes: boolean; reason?: string } {
    // Check source filter
    if (subscription.sources.length > 0 && !subscription.sources.includes(entry.source)) {
      return { passes: false, reason: 'source_mismatch' };
    }

    const filter = subscription.filter;
    if (!filter) {
      return { passes: true };
    }

    // Check minimum log level
    if (filter.minLevel) {
      const entrySeverity = LOG_LEVEL_SEVERITY[entry.level] ?? 2;
      const minSeverity = LOG_LEVEL_SEVERITY[filter.minLevel] ?? 0;
      if (entrySeverity < minSeverity) {
        return { passes: false, reason: 'level_below_minimum' };
      }
    }

    // Check text pattern (case-insensitive substring match)
    if (filter.pattern) {
      const pattern = filter.pattern.toLowerCase();
      const message = entry.message.toLowerCase();
      if (!message.includes(pattern)) {
        return { passes: false, reason: 'pattern_no_match' };
      }
    }

    // Check regex pattern (with ReDoS protection)
    if (filter.regex) {
      const regex = createSafeRegex(filter.regex, 'i');
      if (regex === null) {
        // Invalid or unsafe regex - reject for security
        this.logger.warn({ regex: filter.regex }, 'Rejected unsafe or invalid regex in filter');
        return { passes: false, reason: 'regex_invalid_or_unsafe' };
      }
      const matchResult = testRegexWithTimeout(regex, entry.message);
      if (matchResult === null) {
        return { passes: false, reason: 'regex_execution_error' };
      }
      if (!matchResult) {
        return { passes: false, reason: 'regex_no_match' };
      }
    }

    // Check component filter
    if (filter.components && filter.components.length > 0) {
      if (!entry.component || !filter.components.includes(entry.component)) {
        return { passes: false, reason: 'component_mismatch' };
      }
    }

    // Check time range (since/until)
    if (filter.since && entry.logTimestamp < filter.since) {
      return { passes: false, reason: 'before_since' };
    }
    if (filter.until && entry.logTimestamp > filter.until) {
      return { passes: false, reason: 'after_until' };
    }

    return { passes: true };
  }

  /**
   * Check and update rate limit for a subscription using token bucket.
   *
   * @returns true if entry can be forwarded, false if rate limited
   */
  private checkRateLimit(subscription: LogSubscription): boolean {
    const now = Date.now();
    const state = subscription.rateLimitState;

    // Refill tokens based on elapsed time
    const elapsed = now - state.lastRefill;
    if (elapsed >= this.RATE_LIMIT_REFILL_MS) {
      // Full refill
      state.tokens = subscription.rateLimit;
      state.lastRefill = now;
    } else if (elapsed > 0) {
      // Partial refill based on elapsed time
      const refillAmount = Math.floor((subscription.rateLimit * elapsed) / this.RATE_LIMIT_REFILL_MS);
      if (refillAmount > 0) {
        state.tokens = Math.min(subscription.rateLimit, state.tokens + refillAmount);
        state.lastRefill = now;
      }
    }

    // Try to consume a token
    if (state.tokens > 0) {
      state.tokens--;
      return true;
    }

    return false;
  }

  // ===========================================================================
  // Cleanup
  // ===========================================================================

  /**
   * Clean up all subscriptions for a sensor.
   *
   * Called when a sensor disconnects from the tunnel.
   *
   * @param sensorId - Sensor ID to clean up
   */
  cleanupSensor(sensorId: string): void {
    const subscriptionIds = this.sensorSubscriptions.get(sensorId);
    if (!subscriptionIds) {
      return;
    }

    // Copy set to avoid modification during iteration
    const ids = Array.from(subscriptionIds);
    for (const subscriptionId of ids) {
      const subscription = this.subscriptions.get(subscriptionId);
      if (subscription) {
        // Notify client of disconnection
        try {
          if (subscription.ws.readyState === 1) {
            subscription.ws.send(
              JSON.stringify({
                channel: 'logs',
                type: 'error',
                sessionId: subscriptionId,
                sequenceId: 0,
                timestamp: Date.now(),
                code: 'SENSOR_DISCONNECTED',
                message: `Sensor ${sensorId} disconnected`,
              })
            );
          }
        } catch {
          // Ignore send errors during cleanup
        }
      }
      this.unsubscribe(subscriptionId);
    }

    // Clean up stats
    this.sensorStats.delete(sensorId);
    this.sensorSubscriptions.delete(sensorId);

    this.logger.info({ sensorId, subscriptionCount: ids.length }, 'Cleaned up sensor subscriptions');
  }

  /**
   * Clean up all subscriptions (used during shutdown).
   */
  cleanupAll(): void {
    const sensorIds = Array.from(this.sensorSubscriptions.keys());
    for (const sensorId of sensorIds) {
      this.cleanupSensor(sensorId);
    }
    this.logger.info('Cleaned up all log subscriptions');
  }

  // ===========================================================================
  // Statistics
  // ===========================================================================

  /**
   * Get subscription statistics.
   */
  getStats(): {
    totalSubscriptions: number;
    bySensor: Record<string, number>;
    bySource: Record<LogSource, number>;
  } {
    const bySensor: Record<string, number> = {};
    const bySource: Record<LogSource, number> = {
      system: 0,
      sensor: 0,
      access: 0,
      waf: 0,
      error: 0,
      audit: 0,
      security: 0,
    };

    for (const [sensorId, subscriptionIds] of this.sensorSubscriptions) {
      bySensor[sensorId] = subscriptionIds.size;
    }

    for (const subscription of this.subscriptions.values()) {
      if (subscription.sources.length === 0) {
        // Subscribed to all sources
        bySource.system++;
        bySource.sensor++;
        bySource.access++;
        bySource.error++;
        bySource.audit++;
        bySource.security++;
      } else {
        for (const source of subscription.sources) {
          if (source in bySource) {
            bySource[source]++;
          }
        }
      }
    }

    return {
      totalSubscriptions: this.subscriptions.size,
      bySensor,
      bySource,
    };
  }

  /**
   * Get detailed statistics for a specific sensor.
   */
  getSensorStats(sensorId: string): SensorLogStats | undefined {
    return this.sensorStats.get(sensorId);
  }

  /**
   * Get subscription details by ID.
   */
  getSubscription(subscriptionId: string): {
    sensorId: string;
    sources: LogSource[];
    filter?: LogFilter;
    createdAt: Date;
    entriesReceived: number;
    entriesForwarded: number;
    entriesFiltered: number;
    rateLimit: number;
  } | undefined {
    const sub = this.subscriptions.get(subscriptionId);
    if (!sub) {
      return undefined;
    }

    return {
      sensorId: sub.sensorId,
      sources: sub.sources,
      filter: sub.filter,
      createdAt: sub.createdAt,
      entriesReceived: sub.entriesReceived,
      entriesForwarded: sub.entriesForwarded,
      entriesFiltered: sub.entriesFiltered,
      rateLimit: sub.rateLimit,
    };
  }

  /**
   * Get all subscription IDs for a sensor.
   */
  getSensorSubscriptionIds(sensorId: string): string[] {
    const subscriptionIds = this.sensorSubscriptions.get(sensorId);
    return subscriptionIds ? Array.from(subscriptionIds) : [];
  }

  /**
   * Check if a sensor has any active subscriptions.
   */
  hasSensorSubscriptions(sensorId: string): boolean {
    const subs = this.sensorSubscriptions.get(sensorId);
    return subs !== undefined && subs.size > 0;
  }

  /**
   * Get the total number of active subscriptions.
   */
  get subscriptionCount(): number {
    return this.subscriptions.size;
  }
}

// =============================================================================
// Type-Safe Event Handling
// =============================================================================

/**
 * Augment EventEmitter for type-safe events.
 */
export interface LogStreamer {
  on<K extends keyof LogStreamerEvents>(event: K, listener: LogStreamerEvents[K]): this;
  off<K extends keyof LogStreamerEvents>(event: K, listener: LogStreamerEvents[K]): this;
  emit<K extends keyof LogStreamerEvents>(
    event: K,
    ...args: Parameters<LogStreamerEvents[K]>
  ): boolean;
}
