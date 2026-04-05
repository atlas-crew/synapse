/**
 * Apparatus SSE Bridge
 *
 * Connects to an Apparatus instance's /sse endpoint using Node.js native
 * fetch streaming, parses the event stream, and feeds adapted signals
 * into the Horizon aggregator pipeline.
 *
 * This avoids needing browser EventSource or polyfills — uses only
 * Node.js built-in APIs (fetch + ReadableStream).
 */

import type { Logger } from 'pino';
import { adaptApparatusEvent, type AdaptedSignal } from './apparatusSignalAdapter.js';
import type { Aggregator, IncomingSignal } from './aggregator/index.js';
import type { ApparatusService } from './apparatus.js';
import type { SSEEvent, SSEEventType } from '@atlascrew/apparatus-lib';

// ============================================================================
// Types
// ============================================================================

export interface SSEBridgeConfig {
  /** Apparatus base URL (e.g., http://localhost:8090) */
  apparatusUrl: string;
  /** Tenant ID to tag signals with */
  tenantId: string;
  /** Virtual sensor ID for Apparatus signals */
  sensorId: string;
  /** Reconnect delay in ms (default: 5000) */
  reconnectDelayMs?: number;
  /** Max reconnect attempts before giving up (0 = infinite, default: 0) */
  maxReconnectAttempts?: number;
}

type BridgeState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

// ============================================================================
// SSE Bridge
// ============================================================================

export class ApparatusSSEBridge {
  private readonly config: Required<SSEBridgeConfig>;
  private readonly logger: Logger;
  private readonly aggregator: Aggregator;
  private state: BridgeState = 'disconnected';
  private abortController: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private eventsReceived = 0;
  private eventsAdapted = 0;
  private stopped = false;

  constructor(
    config: SSEBridgeConfig,
    aggregator: Aggregator,
    _apparatusService: ApparatusService,
    logger: Logger,
  ) {
    this.config = {
      reconnectDelayMs: 5000,
      maxReconnectAttempts: 0,
      ...config,
    };
    this.aggregator = aggregator;
    this.logger = logger.child({ service: 'apparatus-sse-bridge' });
  }

  /** Start consuming the SSE stream */
  async start(): Promise<void> {
    if (this.state !== 'disconnected') return;
    this.stopped = false;
    await this.connect();
  }

  /** Stop consuming and clean up */
  stop(): void {
    this.stopped = true;
    this.abortController?.abort();
    this.abortController = null;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.state = 'disconnected';
    this.logger.info(
      { eventsReceived: this.eventsReceived, eventsAdapted: this.eventsAdapted },
      'Apparatus SSE bridge stopped',
    );
  }

  /** Current bridge state */
  getState(): BridgeState {
    return this.state;
  }

  /** Stats for monitoring */
  getStats() {
    return {
      state: this.state,
      eventsReceived: this.eventsReceived,
      eventsAdapted: this.eventsAdapted,
      reconnectAttempts: this.reconnectAttempts,
    };
  }

  // ==========================================================================
  // Connection
  // ==========================================================================

  private async connect(): Promise<void> {
    if (this.stopped) return;

    this.state = this.reconnectAttempts > 0 ? 'reconnecting' : 'connecting';
    this.abortController = new AbortController();

    const url = `${this.config.apparatusUrl}/sse`;

    try {
      this.logger.info({ url, attempt: this.reconnectAttempts }, 'Connecting to Apparatus SSE');

      const response = await fetch(url, {
        headers: { Accept: 'text/event-stream' },
        signal: this.abortController.signal,
      });

      if (!response.ok) {
        throw new Error(`SSE connection failed: HTTP ${response.status}`);
      }

      if (!response.body) {
        throw new Error('SSE response has no body');
      }

      this.state = 'connected';
      this.reconnectAttempts = 0;
      this.logger.info({ url }, 'Connected to Apparatus SSE stream');

      await this.consumeStream(response.body);
    } catch (err: unknown) {
      if (this.stopped) return;

      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('abort')) return; // intentional disconnect

      this.logger.warn({ err: message, attempt: this.reconnectAttempts }, 'Apparatus SSE connection lost');
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;

    const { maxReconnectAttempts, reconnectDelayMs } = this.config;
    if (maxReconnectAttempts > 0 && this.reconnectAttempts >= maxReconnectAttempts) {
      this.logger.error({ attempts: this.reconnectAttempts }, 'Max SSE reconnect attempts reached');
      this.state = 'disconnected';
      return;
    }

    this.reconnectAttempts++;
    // Exponential backoff: delay * 2^attempt, capped at 60s
    const delay = Math.min(reconnectDelayMs * Math.pow(2, this.reconnectAttempts - 1), 60_000);
    this.state = 'reconnecting';

    this.logger.info({ delay, attempt: this.reconnectAttempts }, 'Scheduling SSE reconnect');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch(() => {});
    }, delay);
  }

  // ==========================================================================
  // Stream consumption
  // ==========================================================================

  private async consumeStream(body: ReadableStream<Uint8Array>): Promise<void> {
    const decoder = new TextDecoder();
    const reader = body.getReader();

    let buffer = '';
    let currentEvent = '';
    let currentData = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        // Normalize CRLF → LF (SSE spec permits both)
        const lines = buffer.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
        // Keep the last incomplete line in the buffer
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            // SSE spec: consecutive data lines are joined with \n
            currentData = currentData ? currentData + '\n' + line.slice(6) : line.slice(6);
          } else if (line === '' && currentEvent && currentData) {
            // End of SSE message — dispatch
            this.handleEvent(currentEvent, currentData);
            currentEvent = '';
            currentData = '';
          }
          // Ignore comment lines (: heartbeat ...)
        }
      }
    } finally {
      reader.releaseLock();
    }

    // Stream ended — reconnect unless stopped
    if (!this.stopped) {
      this.logger.info('Apparatus SSE stream ended');
      this.scheduleReconnect();
    }
  }

  // ==========================================================================
  // Event handling
  // ==========================================================================

  private handleEvent(eventType: string, jsonData: string): void {
    this.eventsReceived++;

    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonData);
    } catch {
      this.logger.warn({ eventType }, 'Failed to parse SSE event data');
      return;
    }

    const sseEvent: SSEEvent = {
      type: eventType as SSEEventType,
      timestamp: (parsed as Record<string, unknown>)?.timestamp as string ?? new Date().toISOString(),
      data: parsed,
    };

    const adapted = adaptApparatusEvent(sseEvent);
    if (!adapted) return; // Non-signal event (request, health)

    this.eventsAdapted++;
    this.dispatchSignal(adapted);
  }

  private dispatchSignal(adapted: AdaptedSignal): void {
    const incoming: IncomingSignal = {
      ...adapted.signal,
      tenantId: this.config.tenantId,
      sensorId: this.config.sensorId,
    };

    const result = this.aggregator.queueSignal(incoming);
    if (!result.accepted) {
      this.logger.warn(
        { reason: result.reason, queueSize: result.queueSize },
        'Apparatus signal rejected by aggregator',
      );
    }
  }
}
