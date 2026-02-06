/**
 * Job Queue Configuration
 *
 * BullMQ-based queue for background job processing.
 * Uses Redis for job storage and coordination.
 */

import { Queue, Worker, type Job, type QueueOptions, type WorkerOptions } from 'bullmq';
import type { Logger } from 'pino';

// Queue names for different job types
export const QUEUE_NAMES = {
  ROLLOUT: 'rollout-jobs',
  RETENTION: 'data-retention',
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

/**
 * Job data for rollout execution
 */
export interface RolloutJobData {
  tenantId: string;
  rolloutId: string;
  release: {
    id: string;
    version: string;
    binaryUrl: string;
    sha256: string;
    size: number;
    changelog: string;
  };
  sensors: Array<{
    id: string;
    name: string;
    version: string | null;
  }>;
  options: {
    strategy: string;
    batchSize: number;
    batchDelay: number;
  };
}

/**
 * Redis connection configuration including optional TLS.
 */
export interface RedisConnectionConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  tls?: Record<string, never>;
}

/**
 * Get Redis connection configuration from environment.
 *
 * TLS is enabled when:
 * - The REDIS_URL uses the `rediss://` scheme, or
 * - The REDIS_TLS_ENABLED env var is set to "true"
 */
export function getRedisConfig(): RedisConnectionConfig {
  const redisUrl = process.env.REDIS_URL;
  const tlsExplicit = process.env.REDIS_TLS_ENABLED === 'true';

  if (redisUrl) {
    try {
      const url = new URL(redisUrl);
      const useTls = url.protocol === 'rediss:' || tlsExplicit;
      return {
        host: url.hostname,
        port: parseInt(url.port, 10) || 6379,
        password: url.password || undefined,
        db: url.pathname ? parseInt(url.pathname.slice(1), 10) : undefined,
        ...(useTls ? { tls: {} } : {}),
      };
    } catch {
      // Fall through to defaults if URL parsing fails
    }
  }

  // Defaults for local development
  return {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
    ...(tlsExplicit ? { tls: {} } : {}),
  };
}

/**
 * Create a BullMQ queue with standard configuration
 */
export function createQueue<T>(
  name: QueueName,
  logger: Logger,
  options?: Partial<QueueOptions>
): Queue<T> {
  const redisConfig = getRedisConfig();

  const queue = new Queue<T>(name, {
    connection: redisConfig,
    defaultJobOptions: {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 5000, // 5 seconds initial delay
      },
      removeOnComplete: {
        count: 100, // Keep last 100 completed jobs
        age: 24 * 60 * 60, // Remove after 24 hours
      },
      removeOnFail: {
        count: 500, // Keep last 500 failed jobs for debugging
        age: 7 * 24 * 60 * 60, // Remove after 7 days
      },
    },
    ...options,
  });

  queue.on('error', (error: Error) => {
    logger.error({ error, queue: name }, 'Queue error');
  });

  logger.info({ queue: name, redis: `${redisConfig.host}:${redisConfig.port}` }, 'Queue created');

  return queue;
}

/**
 * Create a BullMQ worker with standard configuration
 */
export function createWorker<T, R>(
  name: QueueName,
  processor: (job: Job<T>) => Promise<R>,
  logger: Logger,
  options?: Partial<WorkerOptions>
): Worker<T, R> {
  const redisConfig = getRedisConfig();

  const worker = new Worker<T, R>(name, processor, {
    connection: redisConfig,
    concurrency: 1, // Process one rollout at a time by default
    lockDuration: 600000, // 10 minutes lock (rollouts can take a while)
    lockRenewTime: 300000, // Renew lock every 5 minutes
    ...options,
  });

  worker.on('completed', (job: Job<T, R>) => {
    logger.info({ jobId: job.id, queue: name }, 'Job completed');
  });

  worker.on('failed', (job: Job<T, R> | undefined, error: Error) => {
    logger.error({ jobId: job?.id, error, queue: name }, 'Job failed');
  });

  worker.on('error', (error: Error) => {
    logger.error({ error, queue: name }, 'Worker error');
  });

  worker.on('active', (job: Job<T, R>) => {
    logger.info({ jobId: job.id, queue: name }, 'Job started processing');
  });

  worker.on('stalled', (jobId: string) => {
    logger.warn({ jobId, queue: name }, 'Job stalled');
  });

  logger.info({ queue: name, concurrency: options?.concurrency ?? 1 }, 'Worker created');

  return worker;
}

/**
 * Gracefully close a queue
 */
export async function closeQueue(queue: Queue, logger: Logger): Promise<void> {
  try {
    await queue.close();
    logger.info({ queue: queue.name }, 'Queue closed');
  } catch (error) {
    logger.error({ error, queue: queue.name }, 'Error closing queue');
  }
}

/**
 * Gracefully close a worker
 */
export async function closeWorker(worker: Worker, logger: Logger): Promise<void> {
  try {
    await worker.close();
    logger.info({ queue: worker.name }, 'Worker closed');
  } catch (error) {
    logger.error({ error, queue: worker.name }, 'Error closing worker');
  }
}
