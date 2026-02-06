import type { Logger } from 'pino';
import RedisModule from 'ioredis';
import type { Redis } from 'ioredis';

import { getRedisConfig } from '../../jobs/queue.js';
import { createIoredisKv, type IoredisLikeClient, type RedisKv } from './kv.js';

// Handle ESM/CJS interop for ioredis (same pattern as pubsub.ts)
const RedisClient = (RedisModule as any).default || RedisModule;

export interface SharedRedisKv {
  kv: RedisKv;
  /** The underlying ioredis client, exposed for health checks (e.g. ping). */
  client: Redis;
  close: () => Promise<void>;
}

let shared: SharedRedisKv | null = null;
let initializing: Promise<SharedRedisKv> | null = null;

/**
 * Create a shared Redis key/value adapter using a direct ioredis client.
 *
 * Previous versions piggy-backed on a BullMQ Queue to obtain the underlying
 * ioredis connection. This version creates a dedicated ioredis client directly,
 * removing the unnecessary BullMQ dependency for state storage.
 */
export async function getSharedRedisKv(logger: Logger): Promise<SharedRedisKv> {
  if (shared) return shared;
  if (initializing) return initializing;

  initializing = (async () => {
    const config = getRedisConfig();
    const client: Redis = new RedisClient(config);

    try {
      const timeoutMs = 2000;
      await Promise.race([
        client.ping(),
        new Promise<void>((_, reject) =>
          setTimeout(() => reject(new Error(`Redis connection timeout after ${timeoutMs}ms`)), timeoutMs)
        ),
      ]);
    } catch (error) {
      // Ensure we don't leak sockets on boot failure.
      await client.quit().catch(() => {});
      throw error;
    }

    const kv = createIoredisKv(client as unknown as IoredisLikeClient);

    shared = {
      kv,
      client,
      close: async () => {
        try {
          await client.quit();
        } catch (error) {
          logger.warn({ error }, 'Failed to close shared Redis client');
        } finally {
          shared = null;
        }
      },
    };

    return shared;
  })();

  try {
    return await initializing;
  } finally {
    // Allow retries if init failed.
    if (!shared) initializing = null;
  }
}
