/**
 * Sigma Hunt Queue
 *
 * Schedules background Sigma hunts via BullMQ to avoid multi-instance overlap.
 */

import type { Logger } from 'pino';
import type { Job, Queue, Worker } from 'bullmq';
import { createQueue, createWorker, QUEUE_NAMES } from './queue.js';
import type { SigmaHuntService } from '../services/sigma-hunt/index.js';

export interface SigmaHuntJobData {
  trigger: 'startup' | 'schedule' | 'manual';
}

export function createSigmaHuntQueue(logger: Logger): Queue<SigmaHuntJobData> {
  return createQueue<SigmaHuntJobData>(QUEUE_NAMES.SIGMA_HUNT, logger, {
    defaultJobOptions: {
      attempts: 2,
      backoff: {
        type: 'exponential',
        delay: 5000,
      },
      removeOnComplete: {
        count: 25,
        age: 24 * 60 * 60,
      },
      removeOnFail: {
        count: 50,
        age: 7 * 24 * 60 * 60,
      },
    },
  });
}

export function createSigmaHuntWorker(
  service: SigmaHuntService,
  logger: Logger
): Worker<SigmaHuntJobData, { tenants: number; rules: number; matches: number; leadsUpserted: number }> {
  return createWorker<SigmaHuntJobData, { tenants: number; rules: number; matches: number; leadsUpserted: number }>(
    QUEUE_NAMES.SIGMA_HUNT,
    async (job: Job<SigmaHuntJobData>) => {
      logger.info({ jobId: job.id, trigger: job.data.trigger }, 'Running sigma background hunts');
      return service.runScheduledHunts();
    },
    logger,
    {
      concurrency: 1,
      lockDuration: 30 * 60 * 1000,
      lockRenewTime: 10 * 60 * 1000,
    }
  );
}

