import { Queue } from 'bullmq';
import type { Logger } from 'pino';

import { getRedisConfig } from '../../jobs/queue.js';
import { createIoredisKv, type IoredisLikeClient, type RedisKv } from './kv.js';

export interface SharedRedisKv {
  kv: RedisKv;
  close: () => Promise<void>;
}

let shared: SharedRedisKv | null = null;
let initializing: Promise<SharedRedisKv> | null = null;

/**
 * Create a shared Redis key/value adapter using BullMQ's managed ioredis client.
 *
 * This avoids a direct `ioredis` dependency in the app package (pnpm hoisting),
 * while still giving us a real Redis client for distributed state.
 *
 * Note: this instantiates a BullMQ Queue to obtain the underlying client.
 */
export async function getSharedRedisKv(logger: Logger): Promise<SharedRedisKv> {
  if (shared) return shared;
  if (initializing) return initializing;

  initializing = (async () => {
    const connection = getRedisConfig();
    const queue = new Queue('__sh_state_kv__', {
      connection,
      // Keep BullMQ keys separate from "bull" defaults.
      prefix: 'sh',
    });

    try {
      const timeoutMs = 2000;
      await Promise.race([
        queue.waitUntilReady(),
        new Promise<void>((_, reject) =>
          setTimeout(() => reject(new Error(`Redis connection timeout after ${timeoutMs}ms`)), timeoutMs)
        ),
      ]);
    } catch (error) {
      // Ensure we don't leak sockets on boot failure.
      await queue.close().catch(() => {});
      throw error;
    }

    // BullMQ uses ioredis under the hood.
    const client = (await queue.client) as unknown as IoredisLikeClient;
    const kv = createIoredisKv(client);

    shared = {
      kv,
      close: async () => {
        try {
          await queue.close();
        } catch (error) {
          logger.warn({ error }, 'Failed to close shared Redis/BullMQ queue');
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
