import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { getRedisConfig } from '../../jobs/queue.js';
import RedisModule from 'ioredis';

// Handle ESM/CJS interop for ioredis
const RedisClient = (RedisModule as any).default || RedisModule;

export type PubSubMessageHandler = (channel: string, message: string) => void;

/**
 * Shared Redis Pub/Sub client.
 * Provides a simple interface for broadcasting messages across multiple Hub instances.
 *
 * Tracks connection state and exposes an isHealthy() method for health checks.
 * ioredis autoResubscribe (default: true) handles re-subscription after reconnect;
 * we log the event for visibility.
 */
export class RedisPubSub {
  private pub: Redis;
  private sub: Redis;
  private logger: Logger;
  private handlers: Map<string, Set<PubSubMessageHandler>> = new Map();
  private subConnected = false;

  constructor(logger: Logger) {
    this.logger = logger.child({ service: 'redis-pubsub' });
    const config = getRedisConfig();

    this.pub = new RedisClient(config);
    this.sub = new RedisClient(config);

    this.setupSub();
    this.setupPub();
  }

  private setupPub() {
    this.pub.on('error', (error) => {
      this.logger.error({ error }, 'Redis Pub error');
    });
  }

  private setupSub() {
    this.sub.on('message', (channel, message) => {
      const topicHandlers = this.handlers.get(channel);
      if (topicHandlers) {
        for (const handler of topicHandlers) {
          try {
            handler(channel, message);
          } catch (error) {
            this.logger.error({ error, channel }, 'Error in Pub/Sub message handler');
          }
        }
      }
    });

    // Connection lifecycle events
    this.sub.on('connect', () => {
      this.logger.info('Redis Sub client connected');
    });

    this.sub.on('ready', () => {
      this.subConnected = true;
      const channelCount = this.handlers.size;
      this.logger.info(
        { channels: channelCount },
        `Redis Sub client ready, re-subscribed to ${channelCount} channel(s)`
      );
    });

    this.sub.on('reconnecting', (delay: number) => {
      this.subConnected = false;
      this.logger.warn({ retryDelayMs: delay }, 'Redis Sub client reconnecting');
    });

    this.sub.on('close', () => {
      this.subConnected = false;
      this.logger.warn('Redis Sub client connection closed');
    });

    this.sub.on('end', () => {
      this.subConnected = false;
      this.logger.warn('Redis Sub client connection ended (no more reconnects)');
    });

    this.sub.on('error', (error) => {
      this.logger.error({ error }, 'Redis Sub error');
    });
  }

  /**
   * Whether the subscriber connection is healthy (connected and ready).
   */
  isHealthy(): boolean {
    return this.subConnected;
  }

  /**
   * Subscribe to a channel.
   */
  async subscribe(channel: string, handler: PubSubMessageHandler): Promise<void> {
    if (!this.handlers.has(channel)) {
      this.handlers.set(channel, new Set());
      await this.sub.subscribe(channel);
      this.logger.debug({ channel }, 'Subscribed to Redis channel');
    }
    this.handlers.get(channel)!.add(handler);
  }

  /**
   * Unsubscribe from a channel.
   */
  async unsubscribe(channel: string, handler: PubSubMessageHandler): Promise<void> {
    const topicHandlers = this.handlers.get(channel);
    if (topicHandlers) {
      topicHandlers.delete(handler);
      if (topicHandlers.size === 0) {
        this.handlers.delete(channel);
        await this.sub.unsubscribe(channel);
        this.logger.debug({ channel }, 'Unsubscribed from Redis channel');
      }
    }
  }

  /**
   * Publish a message to a channel.
   */
  async publish(channel: string, message: any): Promise<number> {
    const payload = typeof message === 'string' ? message : JSON.stringify(message);
    return this.pub.publish(channel, payload);
  }

  /**
   * Close connections.
   */
  async close(): Promise<void> {
    this.subConnected = false;
    await Promise.all([this.pub.quit(), this.sub.quit()]);
    this.logger.info('Redis Pub/Sub connections closed');
  }
}
