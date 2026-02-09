/**
 * Jobs Module
 *
 * Exports job queue configuration and workers for background processing.
 */

export {
  QUEUE_NAMES,
  type QueueName,
  type RolloutJobData,
  getRedisConfig,
  createQueue,
  createWorker,
  closeQueue,
  closeWorker,
} from './queue.js';

export {
  createRolloutWorker,
  stopRolloutWorker,
  recoverStalledRollouts,
  type RolloutWorkerConfig,
} from './rollout-worker.js';

export {
  createSigmaHuntQueue,
  createSigmaHuntWorker,
  type SigmaHuntJobData,
} from './sigma-hunt-queue.js';
