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
  HealthCheckResult,
  SensorDeployResult,
  BlueGreenDeploymentState,
  BlueGreenSensorStatus,
} from './types.js';
import type { FleetCommander } from './fleet-commander.js';
import type { DeploymentStateStore } from './deployment-state-store.js';
import { NoopDeploymentStateStore } from './deployment-state-store.js';

/**
 * Error thrown when a tenant attempts to access sensors they don't own
 */
export class TenantIsolationError extends Error {
  constructor(
    public readonly tenantId: string,
    public readonly unauthorizedSensorIds: string[]
  ) {
    super(
      `Tenant ${tenantId} does not have access to sensors: ${unauthorizedSensorIds.join(', ')}`
    );
    this.name = 'TenantIsolationError';
  }
}

export class RuleDistributor {
  private prisma: PrismaClient;
  private logger: Logger;
  private fleetCommander: FleetCommander | null = null;
  /** Track active Blue/Green deployments */
  private activeDeployments: Map<string, BlueGreenDeploymentState> = new Map();
  /** Track scheduled deployment timers for cancellation (deploymentId -> timer) */
  private scheduledTimers: Map<string, NodeJS.Timeout> = new Map();
  private deploymentStateStore: DeploymentStateStore;

  constructor(prisma: PrismaClient, logger: Logger, deploymentStateStore?: DeploymentStateStore) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'rule-distributor' });
    this.deploymentStateStore = deploymentStateStore ?? new NoopDeploymentStateStore();

    // Best-effort: hydrate deployments so status endpoints survive restart.
    void this.hydrateActiveDeployments();
  }

  private async hydrateActiveDeployments(): Promise<void> {
    try {
      const deployments = await this.deploymentStateStore.loadAll();
      for (const deployment of deployments) {
        this.activeDeployments.set(deployment.deploymentId, deployment);
      }
      if (deployments.length > 0) {
        this.logger.info({ count: deployments.length }, 'Hydrated blue/green deployments from state store');
      }
    } catch (error) {
      this.logger.error({ error }, 'Failed to hydrate blue/green deployments from state store');
    }
  }

  private async safeUpsertDeploymentState(state: BlueGreenDeploymentState): Promise<void> {
    try {
      await this.deploymentStateStore.upsert(state);
    } catch (error) {
      this.logger.error({ error, deploymentId: state.deploymentId, tenantId: state.tenantId }, 'Failed to persist deployment state');
    }
  }

  private async safeDeleteDeploymentState(tenantId: string, deploymentId: string): Promise<void> {
    try {
      await this.deploymentStateStore.delete(tenantId, deploymentId);
    } catch (error) {
      this.logger.error({ error, deploymentId, tenantId }, 'Failed to delete deployment state');
    }
  }

  // =============================================================================
  // Tenant Isolation (Security)
  // =============================================================================

  /**
   * Validate that all sensor IDs belong to the specified tenant.
   * CRITICAL: This MUST be called before any operation that modifies sensor state.
   * @throws {TenantIsolationError} if any sensor does not belong to the tenant
   */
  private async validateSensorOwnership(
    tenantId: string,
    sensorIds: string[]
  ): Promise<void> {
    if (sensorIds.length === 0) return;

    // Query all sensors and verify ownership
    const sensors = await this.prisma.sensor.findMany({
      where: {
        id: { in: sensorIds },
      },
      select: {
        id: true,
        tenantId: true,
      },
    });

    const sensorMap = new Map(sensors.map((s) => [s.id, s.tenantId]));
    const unauthorizedSensorIds: string[] = [];

    for (const sensorId of sensorIds) {
      const ownerTenantId = sensorMap.get(sensorId);
      if (!ownerTenantId) {
        // Sensor not found - treat as unauthorized (don't leak info about non-existent sensors)
        unauthorizedSensorIds.push(sensorId);
      } else if (ownerTenantId !== tenantId) {
        // Sensor belongs to different tenant
        unauthorizedSensorIds.push(sensorId);
      }
    }

    if (unauthorizedSensorIds.length > 0) {
      this.logger.warn(
        {
          tenantId,
          unauthorizedSensorIds,
          totalRequested: sensorIds.length,
        },
        'Tenant isolation violation attempted'
      );
      throw new TenantIsolationError(tenantId, unauthorizedSensorIds);
    }
  }

  /**
   * Set fleet commander for rule deployment
   * This is set after construction to avoid circular dependency
   */
  setFleetCommander(commander: FleetCommander): void {
    this.fleetCommander = commander;

    // Listen for command completion to update deployment state
    this.fleetCommander.on('command-success', (cmd) => {
      // Check if this command is related to an active Blue/Green deployment
      const payload = cmd.result as Record<string, unknown> | undefined;
      const deploymentId = payload?.deploymentId as string | undefined;
      
      // Some sensors might return deploymentId in result, others might just ack the command
      // We need to track command IDs -> deployment IDs mapping, or iterate active deployments
      // Since we don't have a direct map, we iterate active deployments to find matching sensor + context
      
      // Optimization: If payload has deploymentId, use it.
      if (deploymentId && this.activeDeployments.has(deploymentId)) {
        // Determine if this was staging or activation
        // This requires context from the command itself, which we don't have here easily
        // But we can infer from the command type 'push_rules' and the payload structure if we had access to the original command payload
        // However, `cmd` from event only has result.
        
        // BETTER APPROACH: Use the payload sent in the command acknowledgment
        // The sensor should echo back the deploymentId and phase (staging/activation)
        
        // For now, let's assume if we get a success for a sensor in an active deployment, we check what we were waiting for
        const deployment = this.activeDeployments.get(deploymentId);
        if (deployment) {
           const status = deployment.sensorStatus.get(cmd.sensorId);
           if (status) {
             if (deployment.status === 'staging' && status.stagingStatus === 'pending') {
               this.updateSensorStagingStatus(deploymentId, cmd.sensorId, true);
             } else if (deployment.status === 'switching') {
               this.updateSensorActivationStatus(deploymentId, cmd.sensorId, true);
             }
           }
        }
      }
    });

    this.fleetCommander.on('command-failed', (cmd) => {
       // Iterate active deployments to find if this command failure impacts them
       // This is O(N) where N is active deployments, usually small
       for (const deployment of this.activeDeployments.values()) {
         const status = deployment.sensorStatus.get(cmd.sensorId);
         if (status) {
           if (deployment.status === 'staging' && status.stagingStatus === 'pending') {
             this.updateSensorStagingStatus(deployment.deploymentId, cmd.sensorId, false, cmd.error);
           }
           // Activation failure handling if needed
         }
       }
    });
  }

  // =============================================================================
  // Rule Sync Status
  // =============================================================================

  /**
   * Get rule sync status across the fleet
   */
  async getRuleSyncStatus(tenantId: string): Promise<RuleSyncStatus[]> {
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
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
  async getSensorRuleStatus(sensorId: string, tenantId: string): Promise<SensorRuleStatus> {
    // Verify ownership first
    const sensor = await this.prisma.sensor.findFirst({
      where: { id: sensorId, tenantId },
    });

    if (!sensor) {
      throw new Error('Sensor not found or access denied');
    }

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
   * @param tenantId - The tenant making the request (required for authorization)
   * @param sensorIds - Target sensor IDs (must belong to tenantId)
   * @param rules - Rules to deploy
   * @throws {TenantIsolationError} if any sensor does not belong to the tenant
   */
  async pushRules(
    tenantId: string,
    sensorIds: string[],
    rules: Rule[]
  ): Promise<DeploymentResult> {
    await this.validateSensorOwnership(tenantId, sensorIds);
    return this.pushRulesWithStrategyInternal(sensorIds, rules, {
      strategy: 'immediate',
    }, tenantId);
  }

  /**
   * Distribute rules by ID to sensors with optional rollout strategy
   * Fetches rule definitions from database and delegates to pushRulesWithStrategy
   * @param tenantId - The tenant making the request (required for authorization)
   * @param ruleIds - IDs of rules to distribute
   * @param sensorIds - Target sensor IDs (must belong to tenantId)
   * @param options - Rollout strategy options (strategy-specific fields optional)
   * @throws {TenantIsolationError} if any sensor does not belong to the tenant
   */
  async distributeRules(
    tenantId: string,
    ruleIds: string[],
    sensorIds: string[],
    options: {
      strategy: RolloutConfig['strategy'];
      // Canary options
      canaryPercentage?: number;
      // Scheduled options
      scheduledTime?: Date;
      // Rolling strategy options
      rollingBatchSize?: number;
      healthCheckTimeout?: number;
      maxFailuresBeforeAbort?: number;
      rollbackOnFailure?: boolean;
      healthCheckIntervalMs?: number;
      // Blue/Green strategy options
      stagingTimeout?: number;
      switchTimeout?: number;
      requireAllSensorsStaged?: boolean;
      minStagedPercentage?: number;
      cleanupDelayMs?: number;
    }
  ): Promise<DeploymentResult> {
    // SECURITY: Validate tenant owns all target sensors BEFORE any operation
    await this.validateSensorOwnership(tenantId, sensorIds);

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

    // Build RolloutConfig from options, including strategy-specific fields
    const config: RolloutConfig = {
      strategy: options.strategy,
      // Canary options
      canaryPercentages: options.canaryPercentage ? [options.canaryPercentage, 50, 100] : undefined,
      // Scheduled options
      scheduledTime: options.scheduledTime,
      // Rolling strategy options
      rollingBatchSize: options.rollingBatchSize,
      healthCheckTimeout: options.healthCheckTimeout,
      maxFailuresBeforeAbort: options.maxFailuresBeforeAbort,
      rollbackOnFailure: options.rollbackOnFailure,
      healthCheckIntervalMs: options.healthCheckIntervalMs,
      // Blue/Green strategy options
      stagingTimeout: options.stagingTimeout,
      switchTimeout: options.switchTimeout,
      requireAllSensorsStaged: options.requireAllSensorsStaged,
      minStagedPercentage: options.minStagedPercentage,
      cleanupDelayMs: options.cleanupDelayMs,
    };

    return this.pushRulesWithStrategyInternal(sensorIds, rules, config, tenantId);
  }

  /**
   * Push rules with a rollout strategy
   * @param tenantId - The tenant making the request (required for authorization)
   * @param sensorIds - Target sensor IDs (must belong to tenantId)
   * @param rules - Rules to deploy
   * @param config - Rollout configuration
   * @throws {TenantIsolationError} if any sensor does not belong to the tenant
   */
  async pushRulesWithStrategy(
    tenantId: string,
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    // SECURITY: Validate tenant owns all target sensors BEFORE any operation
    await this.validateSensorOwnership(tenantId, sensorIds);
    return this.pushRulesWithStrategyInternal(sensorIds, rules, config, tenantId);
  }

  /**
   * Internal method for pushing rules with a rollout strategy.
   * SECURITY NOTE: This method does NOT validate tenant ownership.
   * Callers MUST validate ownership via validateSensorOwnership() first.
   * @param tenantId - Required for FleetCommander calls and scheduled deployments
   */
  private async pushRulesWithStrategyInternal(
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig,
    tenantId: string
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
        deploymentResult = await this.deployImmediate(tenantId, sensorIds, rules);
        break;

      case 'canary':
        deploymentResult = await this.deployCanary(tenantId, sensorIds, rules, config);
        break;

      case 'scheduled':
        deploymentResult = await this.deployScheduled(tenantId, sensorIds, rules, config);
        break;

      case 'rolling':
        deploymentResult = await this.deployRolling(tenantId, sensorIds, rules, config);
        break;

      case 'blue_green':
        deploymentResult = await this.deployBlueGreen(tenantId, sensorIds, rules, config);
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
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deployImmediate(tenantId: string, sensorIds: string[], rules: Rule[]): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not initialized');
    }

    // Compute rules hash
    const rulesHash = await this.computeRulesHash(rules);

    // Create pending sync state for all sensors using batch transaction
    // Batched upserts: O(1) transaction instead of O(sensors × rules) sequential operations
    await this.prisma.$transaction(
      sensorIds.flatMap((sensorId) =>
        rules.map((rule) =>
          this.prisma.ruleSyncState.upsert({
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
          })
        )
      )
    );

    // Send push_rules command to all sensors
    const commandIds = await this.fleetCommander.sendCommandToMultiple(tenantId, sensorIds, {
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
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deployCanary(
    tenantId: string,
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

      const batchResult = await this.deployImmediate(tenantId, batchSensorIds, rules);
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
   * Persists the scheduled deployment to the database for restart recovery
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deployScheduled(
    tenantId: string,
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
      return this.deployImmediate(tenantId, sensorIds, rules);
    }

    // Persist scheduled deployment to database for restart recovery
    const scheduledDeployment = await this.prisma.scheduledDeployment.create({
      data: {
        tenantId,
        sensorIds,
        rules: rules as unknown as object,
        scheduledAt: scheduledTime,
        status: 'PENDING',
      },
    });

    const delayMs = scheduledTime.getTime() - now.getTime();

    this.logger.info(
      { deploymentId: scheduledDeployment.id, scheduledTime, delayMs, sensorCount: sensorIds.length },
      'Scheduling rule deployment (persisted)'
    );

    // Schedule in-memory timer and track it for cancellation
    this.scheduleDeploymentTimer(tenantId, scheduledDeployment.id, sensorIds, rules, delayMs);

    // Return pending result with deployment ID
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
      scheduledDeploymentId: scheduledDeployment.id,
    };
  }

  /**
   * Schedule the in-memory timer for a deployment and track it
   */
  private scheduleDeploymentTimer(
    tenantId: string,
    deploymentId: string,
    sensorIds: string[],
    rules: Rule[],
    delayMs: number
  ): void {
    const timer = setTimeout(() => {
      void this.executeScheduledDeployment(tenantId, deploymentId, sensorIds, rules);
    }, delayMs);

    this.scheduledTimers.set(deploymentId, timer);
  }

  /**
   * Execute a scheduled deployment and update database status
   * @param tenantId - The tenant that owns the deployment (required for FleetCommander)
   */
  private async executeScheduledDeployment(
    tenantId: string,
    deploymentId: string,
    sensorIds: string[],
    rules: Rule[]
  ): Promise<void> {
    // Remove timer from tracking
    this.scheduledTimers.delete(deploymentId);

    try {
      // Mark as executing
      await this.prisma.scheduledDeployment.update({
        where: { id: deploymentId },
        data: { status: 'EXECUTING' },
      });

      this.logger.info(
        { deploymentId, sensorCount: sensorIds.length },
        'Executing scheduled deployment'
      );

      // Execute the actual deployment
      const result = await this.deployImmediate(tenantId, sensorIds, rules);

      // Update with result
      await this.prisma.scheduledDeployment.update({
        where: { id: deploymentId },
        data: {
          status: 'COMPLETED',
          executedAt: new Date(),
          resultSuccess: result.success,
          resultTotalTargets: result.totalTargets,
          resultSuccessCount: result.successCount,
          resultFailureCount: result.failureCount,
        },
      });

      this.logger.info(
        { deploymentId, success: result.success },
        'Scheduled deployment completed'
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      await this.prisma.scheduledDeployment.update({
        where: { id: deploymentId },
        data: {
          status: 'FAILED',
          executedAt: new Date(),
          error: errorMessage,
        },
      });

      this.logger.error(
        { deploymentId, error: errorMessage },
        'Scheduled deployment failed'
      );
    }
  }

  /**
   * Cancel a scheduled deployment
   * @param tenantId - The tenant making the request
   * @param deploymentId - The scheduled deployment ID to cancel
   * @returns true if cancelled, false if not found or already executed
   */
  async cancelScheduledDeployment(tenantId: string, deploymentId: string): Promise<boolean> {
    // Find the deployment and verify tenant ownership
    const deployment = await this.prisma.scheduledDeployment.findUnique({
      where: { id: deploymentId },
    });

    if (!deployment) {
      this.logger.warn({ deploymentId }, 'Scheduled deployment not found');
      return false;
    }

    if (deployment.tenantId !== tenantId) {
      this.logger.warn(
        { deploymentId, tenantId, ownerTenantId: deployment.tenantId },
        'Tenant does not own scheduled deployment'
      );
      return false;
    }

    if (deployment.status !== 'PENDING') {
      this.logger.warn(
        { deploymentId, status: deployment.status },
        'Cannot cancel deployment - not in PENDING status'
      );
      return false;
    }

    // Clear the in-memory timer if it exists
    const timer = this.scheduledTimers.get(deploymentId);
    if (timer) {
      clearTimeout(timer);
      this.scheduledTimers.delete(deploymentId);
    }

    // Update database status
    await this.prisma.scheduledDeployment.update({
      where: { id: deploymentId },
      data: {
        status: 'CANCELLED',
        cancelledAt: new Date(),
      },
    });

    this.logger.info({ deploymentId }, 'Scheduled deployment cancelled');
    return true;
  }

  /**
   * Get scheduled deployments for a tenant
   */
  async getScheduledDeployments(
    tenantId: string,
    options?: { status?: 'PENDING' | 'EXECUTING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' }
  ): Promise<Array<{
    id: string;
    sensorIds: string[];
    scheduledAt: Date;
    status: string;
    createdAt: Date;
  }>> {
    const deployments = await this.prisma.scheduledDeployment.findMany({
      where: {
        tenantId,
        ...(options?.status && { status: options.status }),
      },
      orderBy: { scheduledAt: 'asc' },
      select: {
        id: true,
        sensorIds: true,
        scheduledAt: true,
        status: true,
        createdAt: true,
      },
    });

    return deployments;
  }

  /**
   * Recover pending scheduled deployments on service startup
   * Call this method during service initialization to reschedule any
   * deployments that were pending when the service was restarted
   */
  async recoverScheduledDeployments(): Promise<number> {
    const now = new Date();

    // Find all pending scheduled deployments
    const pendingDeployments = await this.prisma.scheduledDeployment.findMany({
      where: {
        status: 'PENDING',
      },
      orderBy: { scheduledAt: 'asc' },
    });

    let rescheduledCount = 0;
    let expiredCount = 0;

    for (const deployment of pendingDeployments) {
      const rules = deployment.rules as unknown as Rule[];
      const scheduledTime = deployment.scheduledAt;
      const delayMs = scheduledTime.getTime() - now.getTime();

      if (delayMs <= 0) {
        // Scheduled time has passed - execute immediately
        this.logger.info(
          { deploymentId: deployment.id, scheduledAt: scheduledTime },
          'Recovering expired scheduled deployment - executing now'
        );

        // Execute immediately in background - tenantId is stored in the deployment record
        void this.executeScheduledDeployment(deployment.tenantId, deployment.id, deployment.sensorIds, rules);
        expiredCount++;
      } else {
        // Reschedule for the future
        this.logger.info(
          { deploymentId: deployment.id, scheduledAt: scheduledTime, delayMs },
          'Rescheduling pending deployment after restart'
        );

        this.scheduleDeploymentTimer(deployment.tenantId, deployment.id, deployment.sensorIds, rules, delayMs);
        rescheduledCount++;
      }
    }

    this.logger.info(
      {
        totalPending: pendingDeployments.length,
        rescheduled: rescheduledCount,
        executedImmediately: expiredCount,
      },
      'Scheduled deployment recovery complete'
    );

    return pendingDeployments.length;
  }

  /**
   * Rolling deployment: Deploy to sensors one batch at a time
   * with health verification between each deployment
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deployRolling(
    tenantId: string,
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    const batchSize = config.rollingBatchSize ?? 1;
    const healthCheckTimeout = config.healthCheckTimeout ?? 30000;
    const maxFailures = config.maxFailuresBeforeAbort ?? 3;
    const rollbackOnFailure = config.rollbackOnFailure ?? true;

    const deploymentId = this.generateDeploymentId();
    let failureCount = 0;
    const results: SensorDeployResult[] = [];
    const deployedSensors: string[] = [];

    this.logger.info(
      {
        deploymentId,
        totalSensors: sensorIds.length,
        batchSize,
        maxFailures,
      },
      'Starting rolling deployment'
    );

    for (let i = 0; i < sensorIds.length; i += batchSize) {
      const batch = sensorIds.slice(i, i + batchSize);

      this.logger.info(
        {
          deploymentId,
          batch,
          progress: `${i}/${sensorIds.length}`,
        },
        'Deploying to batch'
      );

      // Deploy to current batch
      for (const sensorId of batch) {
        try {
          await this.deploySingleSensor(tenantId, sensorId, rules);
          results.push({ sensorId, status: 'success' });
          deployedSensors.push(sensorId);
        } catch (error) {
          results.push({
            sensorId,
            status: 'failed',
            error: error instanceof Error ? error.message : String(error),
          });
          failureCount++;
        }
      }

      // Wait for health confirmation from batch
      const healthResults = await this.waitForHealthConfirmation(
        batch,
        healthCheckTimeout,
        config.healthCheckIntervalMs ?? 5000
      );

      const unhealthyCount = healthResults.filter((h) => !h.healthy).length;
      if (unhealthyCount > 0) {
        failureCount += unhealthyCount;
        this.logger.warn(
          {
            deploymentId,
            batch,
            unhealthyCount,
            totalFailures: failureCount,
            maxFailures,
          },
          'Health check failures in rolling deployment'
        );

        if (rollbackOnFailure && failureCount >= maxFailures) {
          this.logger.error(
            {
              deploymentId,
              failureCount,
              deployedSensors,
            },
            'Rolling deployment aborted - initiating rollback'
          );

          await this.rollbackDeployment(tenantId, deployedSensors, rules);

          return {
            success: false,
            totalTargets: sensorIds.length,
            successCount: deployedSensors.length - failureCount,
            failureCount,
            pendingCount: sensorIds.length - i - batchSize,
            results: results.map((r) => ({
              sensorId: r.sensorId,
              success: r.status === 'success',
              error: r.error,
            })),
          };
        }
      }

      // Brief pause between batches to allow system stabilization
      if (i + batchSize < sensorIds.length) {
        await this.sleep(1000);
      }
    }

    this.logger.info(
      {
        deploymentId,
        totalDeployed: deployedSensors.length,
        totalFailed: failureCount,
      },
      'Rolling deployment completed'
    );

    return {
      success: failureCount === 0,
      totalTargets: sensorIds.length,
      successCount: deployedSensors.length - failureCount,
      failureCount,
      pendingCount: 0,
      results: results.map((r) => ({
        sensorId: r.sensorId,
        success: r.status === 'success',
        error: r.error,
      })),
    };
  }

  // =============================================================================
  // Blue/Green Deployment Strategy
  // =============================================================================

  /**
   * Deploy rules using blue/green strategy - stage to all sensors, then atomic switch
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deployBlueGreen(
    tenantId: string,
    sensorIds: string[],
    rules: Rule[],
    config: RolloutConfig
  ): Promise<DeploymentResult> {
    const deploymentId = this.generateDeploymentId();
    const stagingTimeout = config.stagingTimeout ?? 60000;
    const switchTimeout = config.switchTimeout ?? 30000;
    const requireAllStaged = config.requireAllSensorsStaged ?? true;
    const minStagedPercentage = config.minStagedPercentage ?? 100;

    this.logger.info(
      {
        deploymentId,
        sensorCount: sensorIds.length,
        stagingTimeout,
      },
      'Starting blue/green deployment'
    );

    // Initialize deployment state
    const deploymentState: BlueGreenDeploymentState = {
      deploymentId,
      tenantId,
      status: 'staging',
      rules,
      sensorStatus: new Map(),
    };
    this.activeDeployments.set(deploymentId, deploymentState);
    await this.safeUpsertDeploymentState(deploymentState);

    try {
      // Phase 1: Stage green deployment to all sensors
      await this.stageGreenDeployment(tenantId, sensorIds, rules, deploymentId);

      // Phase 2: Wait for all sensors to confirm staging
      const stagingResult = await this.waitForStagingComplete(
        sensorIds,
        deploymentId,
        stagingTimeout
      );

      const stagedCount = stagingResult.filter((s) => s.stagingStatus === 'staged').length;
      const stagedPercentage = (stagedCount / sensorIds.length) * 100;

      if (requireAllStaged && stagedCount < sensorIds.length) {
        throw new Error(
          `Staging incomplete: ${stagedCount}/${sensorIds.length} sensors staged`
        );
      }

      if (stagedPercentage < minStagedPercentage) {
        throw new Error(
          `Staging below threshold: ${stagedPercentage.toFixed(1)}% < ${minStagedPercentage}%`
        );
      }

      deploymentState.status = 'staged';
      deploymentState.stagedAt = new Date();
      await this.safeUpsertDeploymentState(deploymentState);

      this.logger.info(
        {
          deploymentId,
          stagedCount,
          totalSensors: sensorIds.length,
        },
        'Green deployment staged successfully'
      );

      // Phase 3: Execute atomic switch
      deploymentState.status = 'switching';
      await this.safeUpsertDeploymentState(deploymentState);
      await this.executeBlueGreenSwitch(tenantId, sensorIds, deploymentId, switchTimeout);

      deploymentState.status = 'active';
      deploymentState.activatedAt = new Date();
      await this.safeUpsertDeploymentState(deploymentState);

      this.logger.info(
        {
          deploymentId,
        },
        'Blue/green switch completed'
      );

      // Phase 4: Schedule cleanup of old blue deployment
      this.scheduleBlueCleanup(deploymentId, config.cleanupDelayMs ?? 300000);

      return {
        success: true,
        totalTargets: sensorIds.length,
        successCount: stagedCount,
        failureCount: sensorIds.length - stagedCount,
        pendingCount: 0,
        results: sensorIds.map((sensorId) => {
          const status = deploymentState.sensorStatus.get(sensorId);
          return {
            sensorId,
            success: status?.stagingStatus === 'staged',
            error: status?.error,
          };
        }),
      };
    } catch (error) {
      deploymentState.status = 'failed';
      await this.safeUpsertDeploymentState(deploymentState);

      this.logger.error(
        {
          deploymentId,
          error: error instanceof Error ? error.message : String(error),
        },
        'Blue/green deployment failed'
      );

      // Attempt to abort the green deployment
      await this.abortGreenDeployment(tenantId, sensorIds, deploymentId);

      return {
        success: false,
        totalTargets: sensorIds.length,
        successCount: 0,
        failureCount: sensorIds.length,
        pendingCount: 0,
        results: sensorIds.map((sensorId) => ({
          sensorId,
          success: false,
          error: error instanceof Error ? error.message : String(error),
        })),
      };
    }
  }

  /**
   * Stage green deployment to all sensors (inactive until switch)
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async stageGreenDeployment(
    tenantId: string,
    sensorIds: string[],
    rules: Rule[],
    deploymentId: string
  ): Promise<void> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not configured');
    }

    const deployment = this.activeDeployments.get(deploymentId);
    if (!deployment) {
      throw new Error('Deployment state not found');
    }

    // Compute rules hash for tracking
    const rulesHash = await this.computeRulesHash(rules);

    // Send staging command to all sensors in parallel
    const stagingPromises = sensorIds.map(async (sensorId) => {
      deployment.sensorStatus.set(sensorId, {
        sensorId,
        stagingStatus: 'pending',
        activeStatus: 'blue',
        lastUpdated: new Date(),
      });

      try {
        await this.fleetCommander!.sendCommand(tenantId, sensorId, {
          type: 'push_rules',
          payload: {
            deploymentId,
            rules,
            hash: rulesHash,
            activate: false, // Stage only, don't activate
          },
        });

        // Update status to pending (will be confirmed by callback)
        const status = deployment.sensorStatus.get(sensorId);
        if (status) {
          status.lastUpdated = new Date();
        }
      } catch (error) {
        const status = deployment.sensorStatus.get(sensorId);
        if (status) {
          status.stagingStatus = 'failed';
          status.error = error instanceof Error ? error.message : String(error);
          status.lastUpdated = new Date();
        }
      }
    });

    await Promise.all(stagingPromises);

    // Persist staged/pending states so other instances (or restart) can observe progress.
    await this.safeUpsertDeploymentState(deployment);
  }

  /**
   * Wait for all sensors to confirm staging complete
   * Monitors the in-memory state which is updated by FleetCommander events
   */
  private async waitForStagingComplete(
    sensorIds: string[],
    deploymentId: string,
    timeout: number
  ): Promise<BlueGreenSensorStatus[]> {
    const startTime = Date.now();
    const deployment = this.activeDeployments.get(deploymentId);

    if (!deployment) {
      throw new Error('Deployment state not found');
    }

    while (Date.now() - startTime < timeout) {
      let allCompleted = true; // Completed means either staged OR failed

      for (const sensorId of sensorIds) {
        const status = deployment.sensorStatus.get(sensorId);

        if (!status || status.stagingStatus === 'pending') {
          allCompleted = false;
          break; // Still waiting for at least one
        }
      }

      if (allCompleted) {
        break;
      }

      await this.sleep(1000); // Poll every 1 second
    }

    return Array.from(deployment.sensorStatus.values());
  }

  /**
   * Execute atomic blue/green switch
   * Note: In this implementation, we rely on in-memory tracking and assume
   * that once the broadcast command succeeds, the switch is complete.
   * In a production system, this would wait for acknowledgments from sensors.
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async executeBlueGreenSwitch(
    tenantId: string,
    _sensorIds: string[],
    deploymentId: string,
    timeout: number
  ): Promise<void> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not configured');
    }

    this.logger.info(
      {
        deploymentId,
        sensorCount: _sensorIds.length,
      },
      'Executing blue/green switch'
    );

    // Broadcast atomic switch command to all sensors belonging to this tenant
    await this.fleetCommander.broadcastCommand(tenantId, {
      type: 'push_rules',
      payload: {
        deploymentId,
        activate: true, // Signal to activate the staged deployment
      },
    });

    // Wait for confirmation with timeout
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      let allSwitched = true;
      const deployment = this.activeDeployments.get(deploymentId);

      if (deployment) {
        for (const status of deployment.sensorStatus.values()) {
          // Only check sensors that successfully staged
          if (status.stagingStatus === 'staged' && status.activeStatus !== 'green') {
            allSwitched = false;
            break;
          }
        }
      } else {
         throw new Error('Deployment state lost during switch');
      }

      if (allSwitched) {
        return;
      }

      await this.sleep(1000);
    }

    throw new Error(`Switch timeout: not all sensors confirmed activation within ${timeout}ms`);
  }

  /**
   * Abort a failed green deployment
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async abortGreenDeployment(
    tenantId: string,
    _sensorIds: string[],
    deploymentId: string
  ): Promise<void> {
    if (!this.fleetCommander) {
      return;
    }

    this.logger.info(
      {
        deploymentId,
      },
      'Aborting green deployment'
    );

    try {
      await this.fleetCommander.broadcastCommand(tenantId, {
        type: 'push_rules',
        payload: {
          deploymentId,
          abort: true,
        },
      });
    } catch (error) {
      this.logger.error(
        {
          deploymentId,
          error: error instanceof Error ? error.message : String(error),
        },
        'Failed to abort green deployment'
      );
    }

    // Clean up deployment state
    this.activeDeployments.delete(deploymentId);
    void this.safeDeleteDeploymentState(tenantId, deploymentId);
  }

  /**
   * Schedule cleanup of retired blue deployment
   */
  private scheduleBlueCleanup(deploymentId: string, delayMs: number): void {
    setTimeout(() => {
      this.logger.info(
        {
          deploymentId,
        },
        'Cleaning up retired blue deployment'
      );

      const deployment = this.activeDeployments.get(deploymentId);
      if (deployment) {
        deployment.status = 'retired';
        deployment.retiredAt = new Date();
        void this.safeUpsertDeploymentState(deployment);
      }

      // Remove from active tracking after some time
      setTimeout(() => {
        const state = this.activeDeployments.get(deploymentId);
        if (state) void this.safeDeleteDeploymentState(state.tenantId, deploymentId);
        this.activeDeployments.delete(deploymentId);
      }, 60000);
    }, delayMs);
  }

  /**
   * Get deployment status for a specific deployment
   */
  public getDeploymentStatus(deploymentId: string): BlueGreenDeploymentState | undefined {
    return this.activeDeployments.get(deploymentId);
  }

  /**
   * List all active deployments
   */
  public listActiveDeployments(): BlueGreenDeploymentState[] {
    return Array.from(this.activeDeployments.values());
  }

  /**
   * Update sensor staging status (called when receiving acknowledgments from sensors)
   * This method allows FleetCommander to report back staging confirmations
   */
  public updateSensorStagingStatus(
    deploymentId: string,
    sensorId: string,
    staged: boolean,
    error?: string
  ): void {
    const deployment = this.activeDeployments.get(deploymentId);
    if (!deployment) return;

    const status = deployment.sensorStatus.get(sensorId);
    if (status) {
      status.stagingStatus = staged ? 'staged' : 'failed';
      status.error = error;
      status.lastUpdated = new Date();
    }

    void this.safeUpsertDeploymentState(deployment);
  }

  /**
   * Update sensor activation status (called when receiving switch confirmations)
   * This method allows FleetCommander to report back activation confirmations
   */
  public updateSensorActivationStatus(
    deploymentId: string,
    sensorId: string,
    activated: boolean
  ): void {
    const deployment = this.activeDeployments.get(deploymentId);
    if (!deployment) return;

    const status = deployment.sensorStatus.get(sensorId);
    if (status) {
      status.activeStatus = activated ? 'green' : 'blue';
      status.lastUpdated = new Date();
    }

    void this.safeUpsertDeploymentState(deployment);
  }

  /**
   * Wait for health confirmation from sensors after deployment
   * Optimized with batch database queries (labs-2j5u.15)
   */
  private async waitForHealthConfirmation(
    sensorIds: string[],
    timeout: number,
    checkInterval: number
  ): Promise<HealthCheckResult[]> {
    const startTime = Date.now();
    const results: Map<string, HealthCheckResult> = new Map();

    // Initialize all as pending
    for (const sensorId of sensorIds) {
      results.set(sensorId, {
        healthy: false,
        sensorId,
        status: 'timeout',
      });
    }

    while (Date.now() - startTime < timeout) {
      const remainingSensorIds = Array.from(results.entries())
        .filter(([_, r]) => !r.healthy)
        .map(([id, _]) => id);

      if (remainingSensorIds.length === 0) break;

      try {
        // Batch query all relevant data for remaining sensors
        const [syncStates, sensors] = await Promise.all([
          this.prisma.ruleSyncState.findMany({
            where: { sensorId: { in: remainingSensorIds } },
          }),
          this.prisma.sensor.findMany({
            where: { id: { in: remainingSensorIds } },
            select: { id: true, lastHeartbeat: true, connectionState: true },
          }),
        ]);

        const syncStateMap = new Map(syncStates.map((s) => [s.sensorId, s]));
        const sensorMap = new Map(sensors.map((s) => [s.id, s]));

        let allBatchHealthy = true;

        for (const sensorId of remainingSensorIds) {
          const syncState = syncStateMap.get(sensorId);
          const sensor = sensorMap.get(sensorId);

          if (!syncState) {
            results.set(sensorId, {
              healthy: false,
              sensorId,
              status: 'unhealthy',
              errorMessage: 'No sync state found',
            });
            allBatchHealthy = false;
            continue;
          }

          if (!sensor) {
            results.set(sensorId, {
              healthy: false,
              sensorId,
              status: 'unhealthy',
              errorMessage: 'Sensor not found',
            });
            allBatchHealthy = false;
            continue;
          }

          // Check heartbeat freshness (within 60 seconds)
          const heartbeatAge = Date.now() - (sensor.lastHeartbeat?.getTime() ?? 0);
          if (heartbeatAge > 60000) {
            results.set(sensorId, {
              healthy: false,
              sensorId,
              status: 'degraded',
              errorMessage: `Stale heartbeat: ${heartbeatAge}ms old`,
            });
            allBatchHealthy = false;
            continue;
          }

          // Check sensor connection state
          if (sensor.connectionState === 'DISCONNECTED') {
            results.set(sensorId, {
              healthy: false,
              sensorId,
              status: 'unhealthy',
              errorMessage: 'Sensor is disconnected',
            });
            allBatchHealthy = false;
            continue;
          }

          // All checks passed for this sensor
          results.set(sensorId, {
            healthy: true,
            sensorId,
            status: 'healthy',
          });
        }

        if (allBatchHealthy) break;
      } catch (error) {
        this.logger.error({ error }, 'Error during batch health check');
        // On error, we'll just wait and retry next interval
      }

      await this.sleep(checkInterval);
    }

    return Array.from(results.values());
  }

  /**
   * Check health status of a single sensor
   */
  private async checkSensorHealth(sensorId: string): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Check sync state from database
      const syncState = await this.prisma.ruleSyncState.findFirst({
        where: { sensorId },
      });

      if (!syncState) {
        return {
          healthy: false,
          sensorId,
          status: 'unhealthy',
          errorMessage: 'No sync state found',
        };
      }

      // Check if sensor reported back successfully
      const sensor = await this.prisma.sensor.findUnique({
        where: { id: sensorId },
        select: {
          lastHeartbeat: true,
          connectionState: true,
        },
      });

      if (!sensor) {
        return {
          healthy: false,
          sensorId,
          status: 'unhealthy',
          errorMessage: 'Sensor not found',
        };
      }

      // Check heartbeat freshness (within 60 seconds)
      const heartbeatAge = Date.now() - (sensor.lastHeartbeat?.getTime() ?? 0);
      if (heartbeatAge > 60000) {
        return {
          healthy: false,
          sensorId,
          status: 'degraded',
          latencyMs: Date.now() - startTime,
          errorMessage: `Stale heartbeat: ${heartbeatAge}ms old`,
        };
      }

      // Check sensor connection state
      if (sensor.connectionState === 'DISCONNECTED') {
        return {
          healthy: false,
          sensorId,
          status: 'unhealthy',
          latencyMs: Date.now() - startTime,
          errorMessage: 'Sensor is disconnected',
        };
      }

      return {
        healthy: true,
        sensorId,
        status: 'healthy',
        latencyMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        healthy: false,
        sensorId,
        status: 'unhealthy',
        latencyMs: Date.now() - startTime,
        errorMessage: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Rollback deployment to previous rules
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async rollbackDeployment(tenantId: string, sensorIds: string[], currentRules: Rule[]): Promise<void> {
    this.logger.info(
      {
        sensorCount: sensorIds.length,
      },
      'Initiating rollback'
    );

    // Get previous rule version from database or use empty set
    // In a real implementation, you'd fetch the previous version
    const previousRules = await this.getPreviousRuleVersion(currentRules);

    for (const sensorId of sensorIds) {
      try {
        await this.deploySingleSensor(tenantId, sensorId, previousRules);
        this.logger.debug({ sensorId }, 'Rollback successful');
      } catch (error) {
        this.logger.error(
          {
            sensorId,
            error: error instanceof Error ? error.message : String(error),
          },
          'Rollback failed for sensor'
        );
      }
    }
  }

  /**
   * Get previous rule version for rollback
   * Queries the FleetCommand history to find the last successful push_rules command
   * and returns those rules for rollback
   */
  private async getPreviousRuleVersion(_currentRules: Rule[]): Promise<Rule[]> {
    // Get the most recent successful push_rules commands to find what rules
    // were deployed before the current deployment
    // We look for the second-to-last successful deployment (since the last one is current)
    const previousCommands = await this.prisma.fleetCommand.findMany({
      where: {
        commandType: 'push_rules',
        status: 'success',
      },
      orderBy: {
        completedAt: 'desc',
      },
      take: 2, // Get the two most recent successful deployments
      select: {
        id: true,
        payload: true,
        completedAt: true,
      },
    });

    // If we have at least 2 successful deployments, use the second one (previous)
    // If only 1, there's no previous state to rollback to
    if (previousCommands.length < 2) {
      this.logger.warn(
        { commandsFound: previousCommands.length },
        'No previous rule deployment found for rollback - returning empty rules'
      );
      return [];
    }

    const previousCommand = previousCommands[1]; // Second-to-last (previous deployment)
    const payload = previousCommand.payload as { rules?: Rule[] } | null;

    if (!payload?.rules || !Array.isArray(payload.rules)) {
      this.logger.warn(
        { commandId: previousCommand.id },
        'Previous command payload does not contain valid rules array'
      );
      return [];
    }

    this.logger.info(
      {
        commandId: previousCommand.id,
        ruleCount: payload.rules.length,
        completedAt: previousCommand.completedAt,
      },
      'Found previous rule version for rollback'
    );

    return payload.rules;
  }

  /**
   * Deploy rules to a single sensor
   * @param tenantId - The tenant making the request (required for FleetCommander)
   */
  private async deploySingleSensor(tenantId: string, sensorId: string, rules: Rule[]): Promise<void> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not configured');
    }

    await this.fleetCommander.sendCommand(tenantId, sensorId, {
      type: 'push_rules',
      payload: { rules },
    });
  }

  /**
   * Generate unique deployment ID
   */
  private generateDeploymentId(): string {
    return `deploy-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
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
   * Uses batch transaction instead of sequential operations
   */
  async bulkUpdateRuleSync(
    sensorId: string,
    updates: Array<{ ruleId: string; status: 'synced' | 'failed'; error?: string }>
  ): Promise<void> {
    if (updates.length === 0) return;

    const now = new Date();

    // Batch all upserts in a single transaction
    await this.prisma.$transaction(
      updates.map((update) =>
        this.prisma.ruleSyncState.upsert({
          where: {
            sensorId_ruleId: {
              sensorId,
              ruleId: update.ruleId,
            },
          },
          create: {
            sensorId,
            ruleId: update.ruleId,
            status: update.status,
            syncedAt: update.status === 'synced' ? now : null,
            error: update.status === 'failed' ? (update.error ?? 'Unknown error') : null,
          },
          update: {
            status: update.status,
            syncedAt: update.status === 'synced' ? now : null,
            error: update.status === 'failed' ? (update.error ?? 'Unknown error') : null,
          },
        })
      )
    );

    // Log summary instead of individual operations
    const syncedCount = updates.filter((u) => u.status === 'synced').length;
    const failedCount = updates.filter((u) => u.status === 'failed').length;

    if (syncedCount > 0) {
      this.logger.info({ sensorId, syncedCount }, 'Rules synced in bulk');
    }
    if (failedCount > 0) {
      this.logger.warn({ sensorId, failedCount }, 'Rules failed in bulk');
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
  async getSensorsWithFailedRules(tenantId: string): Promise<Array<{ sensorId: string; failedRules: string[] }>> {
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
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
   * @param tenantId - The tenant making the request (required for authorization)
   * @param sensorId - Target sensor ID (must belong to tenantId)
   * @throws {TenantIsolationError} if sensor does not belong to the tenant
   */
  async retryFailedRules(tenantId: string, sensorId: string): Promise<DeploymentResult> {
    // SECURITY: Validate tenant owns the sensor BEFORE any operation
    await this.validateSensorOwnership(tenantId, [sensorId]);

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

    const commandId = await this.fleetCommander.sendCommand(tenantId, sensorId, {
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
