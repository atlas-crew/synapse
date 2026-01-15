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

export class RuleDistributor {
  private prisma: PrismaClient;
  private logger: Logger;
  private fleetCommander: FleetCommander | null = null;
  /** Track active Blue/Green deployments */
  private activeDeployments: Map<string, BlueGreenDeploymentState> = new Map();

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

      case 'rolling':
        deploymentResult = await this.deployRolling(sensorIds, rules, config);
        break;

      case 'blue_green':
        deploymentResult = await this.deployBlueGreen(sensorIds, rules, config);
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

  /**
   * Rolling deployment: Deploy to sensors one batch at a time
   * with health verification between each deployment
   */
  private async deployRolling(
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
          await this.deploySingleSensor(sensorId, rules);
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

          await this.rollbackDeployment(deployedSensors, rules);

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
   */
  private async deployBlueGreen(
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
      status: 'staging',
      rules,
      sensorStatus: new Map(),
    };
    this.activeDeployments.set(deploymentId, deploymentState);

    try {
      // Phase 1: Stage green deployment to all sensors
      await this.stageGreenDeployment(sensorIds, rules, deploymentId);

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
      await this.executeBlueGreenSwitch(sensorIds, deploymentId, switchTimeout);

      deploymentState.status = 'active';
      deploymentState.activatedAt = new Date();

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

      this.logger.error(
        {
          deploymentId,
          error: error instanceof Error ? error.message : String(error),
        },
        'Blue/green deployment failed'
      );

      // Attempt to abort the green deployment
      await this.abortGreenDeployment(sensorIds, deploymentId);

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
   */
  private async stageGreenDeployment(
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
        await this.fleetCommander!.sendCommand(sensorId, {
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
  }

  /**
   * Wait for all sensors to confirm staging complete
   * Note: In this implementation, we rely on in-memory tracking since Blue/Green
   * deployments are short-lived operations. The sensor status is updated via
   * command acknowledgments from FleetCommander.
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
      // Check staging status for all sensors from in-memory state
      let allStaged = true;

      for (const sensorId of sensorIds) {
        const status = deployment.sensorStatus.get(sensorId);

        if (!status || status.stagingStatus === 'pending') {
          // In a real implementation, this would check for command acknowledgments
          // For now, we simulate by checking if the command was sent successfully
          // The actual acknowledgment would come via FleetCommander callbacks
          allStaged = false;
        } else if (status.stagingStatus === 'failed') {
          // Failed sensors don't block, but are tracked
          continue;
        }
      }

      if (allStaged) {
        break;
      }

      await this.sleep(2000); // Poll every 2 seconds
    }

    return Array.from(deployment.sensorStatus.values());
  }

  /**
   * Execute atomic blue/green switch
   * Note: In this implementation, we rely on in-memory tracking and assume
   * that once the broadcast command succeeds, the switch is complete.
   * In a production system, this would wait for acknowledgments from sensors.
   */
  private async executeBlueGreenSwitch(
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

    // Broadcast atomic switch command to all sensors
    await this.fleetCommander.broadcastCommand({
      type: 'push_rules',
      payload: {
        deploymentId,
        activate: true, // Signal to activate the staged deployment
      },
    });

    // Wait for confirmation with timeout
    // In this implementation, we simulate waiting for acknowledgments
    const startTime = Date.now();
    const deployment = this.activeDeployments.get(deploymentId);

    while (Date.now() - startTime < timeout) {
      let allSwitched = true;

      // Check in-memory state for activation confirmations
      // In a real implementation, this would be updated via FleetCommander callbacks
      if (deployment) {
        for (const status of deployment.sensorStatus.values()) {
          if (status.activeStatus !== 'green') {
            allSwitched = false;
            break;
          }
        }
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
   */
  private async abortGreenDeployment(
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
      await this.fleetCommander.broadcastCommand({
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
      }

      // Remove from active tracking after some time
      setTimeout(() => {
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
  }

  /**
   * Wait for health confirmation from sensors after deployment
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
      let allHealthy = true;

      for (const sensorId of sensorIds) {
        const currentResult = results.get(sensorId)!;
        if (currentResult.healthy) continue;

        try {
          const health = await this.checkSensorHealth(sensorId);
          results.set(sensorId, health);
          if (!health.healthy) {
            allHealthy = false;
          }
        } catch (error) {
          allHealthy = false;
          results.set(sensorId, {
            healthy: false,
            sensorId,
            status: 'unhealthy',
            errorMessage: error instanceof Error ? error.message : String(error),
          });
        }
      }

      if (allHealthy) {
        break;
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
   */
  private async rollbackDeployment(sensorIds: string[], currentRules: Rule[]): Promise<void> {
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
        await this.deploySingleSensor(sensorId, previousRules);
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
   */
  private async getPreviousRuleVersion(_currentRules: Rule[]): Promise<Rule[]> {
    // Query for previous rule deployment
    // For now, return empty array (effectively disabling rules)
    // In production, this would fetch from rule history table
    return [];
  }

  /**
   * Deploy rules to a single sensor
   */
  private async deploySingleSensor(sensorId: string, rules: Rule[]): Promise<void> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not configured');
    }

    await this.fleetCommander.sendCommand(sensorId, {
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
