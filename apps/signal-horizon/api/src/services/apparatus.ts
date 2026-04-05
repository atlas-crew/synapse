/**
 * Apparatus Integration Service
 *
 * Wraps the @atlascrew/apparatus-lib client and manages the connection
 * lifecycle. Provides typed access to Apparatus APIs from the Horizon
 * API server.
 *
 * The service is lazy — it does not block startup if Apparatus is
 * unreachable, and degrades gracefully when the connection is lost.
 */

import { EventEmitter } from 'node:events';
import {
  ApparatusClient,
  isNetworkError,
  isTimeoutError,
} from '@atlascrew/apparatus-lib';
import type {
  HealthResponse,
  ApparatusClientOptions,
} from '@atlascrew/apparatus-lib';
import type { Logger } from 'pino';

// ============================================================================
// Types
// ============================================================================

export type ApparatusConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface ApparatusStatus {
  state: ApparatusConnectionState;
  url: string | undefined;
  version: string | undefined;
  lastHealthCheck: string | undefined;
  lastError: string | undefined;
}

interface ApparatusServiceEvents {
  'state-change': [state: ApparatusConnectionState, previous: ApparatusConnectionState];
  'health': [response: HealthResponse];
  'error': [error: Error];
}

// ============================================================================
// Service
// ============================================================================

export class ApparatusService extends EventEmitter<ApparatusServiceEvents> {
  private client: ApparatusClient | null = null;
  private state: ApparatusConnectionState = 'disconnected';
  private healthTimer: ReturnType<typeof setInterval> | null = null;
  private lastHealth: HealthResponse | null = null;
  private lastHealthAt: Date | null = null;
  private lastError: string | null = null;
  private readonly log: Logger;
  private readonly url: string | undefined;
  private readonly clientOptions: ApparatusClientOptions | null;
  private readonly healthIntervalMs: number;

  constructor(opts: {
    url?: string;
    timeoutMs?: number;
    healthIntervalMs?: number;
    logger: Logger;
  }) {
    super();
    this.log = opts.logger.child({ service: 'apparatus' });
    this.url = opts.url;
    this.healthIntervalMs = opts.healthIntervalMs ?? 30_000;

    if (opts.url) {
      this.clientOptions = {
        baseUrl: opts.url,
        timeout: opts.timeoutMs ?? 30_000,
      };
    } else {
      this.clientOptions = null;
      this.log.info('Apparatus integration disabled (APPARATUS_URL not set)');
    }
  }

  /** Whether the service is configured (APPARATUS_URL is set) */
  get enabled(): boolean {
    return this.clientOptions !== null;
  }

  /** Current connection state */
  get connectionState(): ApparatusConnectionState {
    return this.state;
  }

  /** Whether we have a healthy connection */
  get isConnected(): boolean {
    return this.state === 'connected';
  }

  /** Get the underlying client (null if not configured or not connected) */
  getClient(): ApparatusClient | null {
    return this.client;
  }

  /** Get a summary of current status */
  getStatus(): ApparatusStatus {
    return {
      state: this.state,
      url: this.url,
      version: this.lastHealth?.version,
      lastHealthCheck: this.lastHealthAt?.toISOString(),
      lastError: this.lastError ?? undefined,
    };
  }

  /**
   * Start the service. Creates the client and begins health checking.
   * Does NOT throw if Apparatus is unreachable — marks as disconnected.
   */
  async start(): Promise<void> {
    if (!this.clientOptions) return;

    this.client = new ApparatusClient(this.clientOptions);
    this.setState('connecting');

    // Initial health check (non-blocking)
    await this.checkHealth();

    // Periodic health checks
    this.healthTimer = setInterval(() => {
      this.checkHealth().catch((err) => {
        this.log.error({ err }, 'Apparatus health check failed');
      });
    }, this.healthIntervalMs);
  }

  /**
   * Stop the service. Clears timers and resets state.
   */
  stop(): void {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
    this.client = null;
    this.setState('disconnected');
  }

  // ==========================================================================
  // Health Checking
  // ==========================================================================

  private async checkHealth(): Promise<void> {
    if (!this.client) return;

    try {
      const health = await this.client.health();
      this.lastHealth = health;
      this.lastHealthAt = new Date();
      this.lastError = null;

      if (health.status === 'ok' || health.status === 'degraded') {
        this.setState('connected');
        this.emit('health', health);
      } else {
        this.setState('error');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.lastError = message;

      if (isNetworkError(err) || isTimeoutError(err)) {
        this.setState('disconnected');
        this.log.warn({ url: this.url }, 'Apparatus unreachable');
      } else {
        this.setState('error');
        this.log.error({ err }, 'Apparatus health check error');
      }

      this.emit('error', err instanceof Error ? err : new Error(message));
    }
  }

  // ==========================================================================
  // Internal
  // ==========================================================================

  private setState(next: ApparatusConnectionState): void {
    if (next === this.state) return;
    const prev = this.state;
    this.state = next;
    this.log.info({ from: prev, to: next }, 'Apparatus connection state changed');
    this.emit('state-change', next, prev);
  }
}
