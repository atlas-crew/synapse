/**
 * Rule Distributor Service
 * Manage rule deployment and synchronization across the sensor fleet
 */

import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type {
  RuleSyncStatus,
  SensorRuleStatus,
  Rule,
  DeploymentResult,
  RolloutConfig,
} from './types.js';
import type { FleetCommander } from './fleet-commander.js';

export class RuleDistributor {
  private prisma: PrismaClient;
  private logger: Logger;
  private fleetCommander: FleetCommander | null = null;

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'rule-distributor' });
  }

  /**
   * Set fleet commander for rule deployment
   * This is set after construction to avoid circular dependency
   */
  setFleetCommander(commander: FleetCommander): void {
    this.fleetCommander = commander;
  }

  // =============================================================================
  // Rule Sync Status
  // =============================================================================

  /**
   * Get rule sync status across the fleet
   */
  async getRuleSyncStatus(): Promise<RuleSyncStatus[]> {
    const sensors = await this.prisma.sensor.findMany({
      include: {
        ruleSyncState: true,
      },
    });

    const statusList: RuleSyncStatus[] = [];

    for (const sensor of sensors) {
      const totalRules = sensor.ruleSyncState.length;
      const syncedRules = sensor.ruleSyncState.filter((r) => r.status === 'synced').length;
      const pendingRules = sensor.ruleSyncState.filter((r) => r.status === 'pending').length;
      const failedRules = sensor.ruleSyncState.filter((r) => r.status === 'failed').length;

      const lastSyncDate = sensor.ruleSyncState
        .filter((r) => r.syncedAt !== null)
        .sort((a, b) => (b.syncedAt?.getTime() ?? 0) - (a.syncedAt?.getTime() ?? 0))[0]?.syncedAt;
      const lastSync = lastSyncDate ?? undefined;

      const errors = sensor.ruleSyncState.filter((r) => r.error !== null).map((r) => r.error!);

      statusList.push({
        sensorId: sensor.id,
        totalRules,
        syncedRules,
        pendingRules,
        failedRules,
        lastSync,
        errors,
      });
    }

    return statusList;
  }

  /**
   * Get rule status for a specific sensor
   */
  async getSensorRuleStatus(sensorId: string): Promise<SensorRuleStatus> {
    const ruleSyncStates = await this.prisma.ruleSyncState.findMany({
      where: { sensorId },
      orderBy: { createdAt: 'desc' },
    });

    const rules = ruleSyncStates.map((state) => ({
      ruleId: state.ruleId,
      status: state.status as 'pending' | 'synced' | 'failed',
      syncedAt: state.syncedAt ?? undefined,
      error: state.error ?? undefined,
    }));

    return {
      sensorId,
      rules,
    };
  }

  // =============================================================================
  // Rule Deployment
  // =============================================================================

  /**
   * Push rules to sensors immediately
   */
  async pushRules(sensorIds: string[], rules: Rule[]): Promise<DeploymentResult> {
    return this.pushRulesWithStrategy(sensorIds, rules, {
      strategy: 'immediate',
    });
  }

  /**
   * Distribute rules by ID to sensors with optional rollout strategy
   * Fetches rule definitions from database and delegates to pushRulesWithStrategy
   */
  async distributeRules(
    ruleIds: string[],
    sensorIds: string[],
    options: { strategy: RolloutConfig['strategy']; canaryPercentage?: number }
  ): Promise<DeploymentResult> {
    // For now, create minimal rule objects with just the IDs
    // In a full implementation, rules would be fetched from a rules table
    const rules: Rule[] = ruleIds.map((id, index) => ({
      id,
      name: `Rule ${id}`,
      enabled: true,
      conditions: {},
      actions: {},
      priority: index,
    }));

    const config: RolloutConfig = {
      strategy: options.strategy,
      canaryPercentages: options.canaryPercentage ? [options.canaryPercentage, 50, 100] : undefined,
    };

    return this.pushRulesWithStrategy(sensorIds, rules, config);
  }

  /**
   * Push rules with a rollout strategy
   */
  async pushRulesWithStrategy(
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not initialized');
    }

    this.logger.info(
      { sensorCount: sensorIds.length, ruleCount: rules.length, strategy: config.strategy },
      'Pushing rules to sensors'
    );

    let deploymentResult: DeploymentResult;

    switch (config.strategy) {
      case 'immediate':
        deploymentResult = await this.deployImmediate(sensorIds, rules);
        break;

      case 'canary':
        deploymentResult = await this.deployCanary(sensorIds, rules, config);
        break;

      case 'scheduled':
        deploymentResult = await this.deployScheduled(sensorIds, rules, config);
        break;

      default:
        throw new Error(`Unknown rollout strategy: ${config.strategy}`);
    }

    return deploymentResult;
  }

  // =============================================================================
  // Rollout Strategies
  // =============================================================================

  /**
   * Immediate deployment: Push to all sensors at once
   */
  private async deployImmediate(sensorIds: string[], rules: Rule[]): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not initialized');
    }

    // Compute rules hash
    const rulesHash = await this.computeRulesHash(rules);

    // Create pending sync state for all sensors
    for (const sensorId of sensorIds) {
      for (const rule of rules) {
        await this.prisma.ruleSyncState.upsert({
          where: {
            sensorId_ruleId: {
              sensorId,
              ruleId: rule.id,
            },
          },
          create: {
            sensorId,
            ruleId: rule.id,
            status: 'pending',
          },
          update: {
            status: 'pending',
            syncedAt: null,
            error: null,
          },
        });
      }
    }

    // Send push_rules command to all sensors
    const commandIds = await this.fleetCommander.sendCommandToMultiple(sensorIds, {
      type: 'push_rules',
      payload: {
        rules,
        hash: rulesHash,
      },
    });

    const results: DeploymentResult['results'] = [];
    for (let i = 0; i < sensorIds.length; i++) {
      results.push({
        sensorId: sensorIds[i],
        success: true, // Will be updated when command completes
        commandId: commandIds[i],
      });
    }

    return {
      success: true,
      totalTargets: sensorIds.length,
      successCount: 0,
      failureCount: 0,
      pendingCount: sensorIds.length,
      results,
    };
  }

  /**
   * Canary deployment: Roll out to 10% → 50% → 100% with delays
   */
  private async deployCanary(
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    const percentages = config.canaryPercentages ?? [10, 50, 100];
    const delayBetweenStages = config.delayBetweenStages ?? 60000; // 1 minute default

    this.logger.info(
      { percentages, delayBetweenStages },
      'Starting canary deployment'
    );

    const totalSensors = sensorIds.length;
    let deployedCount = 0;
    const allResults: DeploymentResult['results'] = [];

    for (const percentage of percentages) {
      const targetCount = Math.ceil((totalSensors * percentage) / 100);
      const batchSize = targetCount - deployedCount;

      if (batchSize <= 0) continue;

      const batchSensorIds = sensorIds.slice(deployedCount, deployedCount + batchSize);

      this.logger.info(
        { stage: percentage, batchSize, deployedCount, targetCount },
        'Deploying canary batch'
      );

      const batchResult = await this.deployImmediate(batchSensorIds, rules);
      allResults.push(...batchResult.results);
      deployedCount += batchSize;

      // Wait before next stage (except for the last stage)
      if (percentage < 100) {
        this.logger.info({ delayMs: delayBetweenStages }, 'Waiting before next canary stage');
        await new Promise((resolve) => setTimeout(resolve, delayBetweenStages));
      }
    }

    return {
      success: true,
      totalTargets: sensorIds.length,
      successCount: 0,
      failureCount: 0,
      pendingCount: sensorIds.length,
      results: allResults,
    };
  }

  /**
   * Scheduled deployment: Push at a specific time
   */
  private async deployScheduled(
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    if (!config.scheduledTime) {
      throw new Error('Scheduled deployment requires scheduledTime');
    }

    const now = new Date();
    const scheduledTime = config.scheduledTime;

    if (scheduledTime <= now) {
      this.logger.warn('Scheduled time is in the past, deploying immediately');
      return this.deployImmediate(sensorIds, rules);
    }

    const delayMs = scheduledTime.getTime() - now.getTime();

    this.logger.info(
      { scheduledTime, delayMs },
      'Scheduling rule deployment'
    );

    // Schedule deployment
    setTimeout(() => {
      void this.deployImmediate(sensorIds, rules);
    }, delayMs);

    // Return pending result
    const results: DeploymentResult['results'] = sensorIds.map((sensorId) => ({
      sensorId,
      success: true,
    }));

    return {
      success: true,
      totalTargets: sensorIds.length,
      successCount: 0,
      failureCount: 0,
      pendingCount: sensorIds.length,
      results,
    };
  }

  // =============================================================================
  // Update Rule Sync State (called by WebSocket handler)
  // =============================================================================

  /**
   * Mark rule as synced for a sensor
   */
  async markRuleSynced(sensorId: string, ruleId: string): Promise<void> {
    await this.prisma.ruleSyncState.upsert({
      where: {
        sensorId_ruleId: {
          sensorId,
          ruleId,
        },
      },
      create: {
        sensorId,
        ruleId,
        status: 'synced',
        syncedAt: new Date(),
      },
      update: {
        status: 'synced',
        syncedAt: new Date(),
        error: null,
      },
    });

    this.logger.info({ sensorId, ruleId }, 'Rule synced');
  }

  /**
   * Mark rule as failed for a sensor
   */
  async markRuleFailed(sensorId: string, ruleId: string, error: string): Promise<void> {
    await this.prisma.ruleSyncState.upsert({
      where: {
        sensorId_ruleId: {
          sensorId,
          ruleId,
        },
      },
      create: {
        sensorId,
        ruleId,
        status: 'failed',
        error,
      },
      update: {
        status: 'failed',
        error,
      },
    });

    this.logger.warn({ sensorId, ruleId, error }, 'Rule sync failed');
  }

  /**
   * Bulk update rule sync states
   */
  async bulkUpdateRuleSync(
    sensorId: string,
    updates: Array<{ ruleId: string; status: 'synced' | 'failed'; error?: string }>
  ): Promise<void> {
    for (const update of updates) {
      if (update.status === 'synced') {
        await this.markRuleSynced(sensorId, update.ruleId);
      } else {
        await this.markRuleFailed(sensorId, update.ruleId, update.error ?? 'Unknown error');
      }
    }
  }

  // =============================================================================
  // Helpers
  // =============================================================================

  /**
   * Compute hash of rules for sync tracking
   */
  private async computeRulesHash(rules: Rule[]): Promise<string> {
    // Sort rules by ID for consistent hashing
    const sortedRules = [...rules].sort((a, b) => a.id.localeCompare(b.id));
    const rulesString = JSON.stringify(sortedRules);

    const encoder = new TextEncoder();
    const data = encoder.encode(rulesString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Get sensors with failed rule syncs
   */
  async getSensorsWithFailedRules(): Promise<Array<{ sensorId: string; failedRules: string[] }>> {
    const sensors = await this.prisma.sensor.findMany({
      include: {
        ruleSyncState: {
          where: {
            status: 'failed',
          },
        },
      },
    });

    return sensors
      .filter((s) => s.ruleSyncState.length > 0)
      .map((s) => ({
        sensorId: s.id,
        failedRules: s.ruleSyncState.map((r) => r.ruleId),
      }));
  }

  /**
   * Retry failed rule syncs for a sensor
   */
  async retryFailedRules(sensorId: string): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not initialized');
    }

    const failedStates = await this.prisma.ruleSyncState.findMany({
      where: {
        sensorId,
        status: 'failed',
      },
    });

    if (failedStates.length === 0) {
      return {
        success: true,
        totalTargets: 0,
        successCount: 0,
        failureCount: 0,
        pendingCount: 0,
        results: [],
      };
    }

    this.logger.info(
      { sensorId, failedCount: failedStates.length },
      'Retrying failed rule syncs'
    );

    // In a real implementation, you would fetch the actual rule definitions
    // For now, we'll just mark them as pending and send a generic retry command
    for (const state of failedStates) {
      await this.prisma.ruleSyncState.update({
        where: { id: state.id },
        data: {
          status: 'pending',
          error: null,
        },
      });
    }

    const commandId = await this.fleetCommander.sendCommand(sensorId, {
      type: 'push_rules',
      payload: {
        ruleIds: failedStates.map((s) => s.ruleId),
        retry: true,
      },
    });

    return {
      success: true,
      totalTargets: 1,
      successCount: 0,
      failureCount: 0,
      pendingCount: 1,
      results: [
        {
          sensorId,
          success: true,
          commandId,
        },
      ],
    };
  }
}
