/**
 * Configuration Manager Service
 * Manage configuration templates and sync state across the fleet
 */

import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import type {
  ConfigTemplate,
  ConfigSyncState,
  FleetSyncStatus,
  ConfigDiff,
  DeploymentResult,
} from './types.js';
import type { FleetCommander } from './fleet-commander.js';

export class ConfigManager {
  private prisma: PrismaClient;
  private logger: Logger;
  private fleetCommander: FleetCommander | null = null;

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'config-manager' });
  }

  /**
   * Set fleet commander for config deployment
   * This is set after construction to avoid circular dependency
   */
  setFleetCommander(commander: FleetCommander): void {
    this.fleetCommander = commander;
  }

  // =============================================================================
  // Config Template CRUD
  // =============================================================================

  /**
   * Create a new configuration template
   */
  async createTemplate(template: Omit<ConfigTemplate, 'id' | 'createdAt' | 'updatedAt'>): Promise<ConfigTemplate> {
    this.logger.info({ name: template.name, environment: template.environment }, 'Creating config template');

    const created = await this.prisma.configTemplate.create({
      data: {
        name: template.name,
        description: template.description,
        environment: template.environment,
        config: template.config as Prisma.InputJsonValue,
        hash: template.hash,
        version: template.version,
        isActive: template.isActive,
      },
    });

    return this.mapTemplate(created);
  }

  /**
   * Get a configuration template by ID
   */
  async getTemplate(templateId: string): Promise<ConfigTemplate | null> {
    const template = await this.prisma.configTemplate.findUnique({
      where: { id: templateId },
    });

    return template ? this.mapTemplate(template) : null;
  }

  /**
   * List all configuration templates
   */
  async listTemplates(filters?: { environment?: string; isActive?: boolean }): Promise<ConfigTemplate[]> {
    const templates = await this.prisma.configTemplate.findMany({
      where: {
        environment: filters?.environment,
        isActive: filters?.isActive,
      },
      orderBy: { createdAt: 'desc' },
    });

    return templates.map((t) => this.mapTemplate(t));
  }

  /**
   * Update a configuration template
   */
  async updateTemplate(
    templateId: string,
    updates: Partial<Omit<ConfigTemplate, 'id' | 'createdAt' | 'updatedAt'>>
  ): Promise<ConfigTemplate> {
    this.logger.info({ templateId }, 'Updating config template');

    const updated = await this.prisma.configTemplate.update({
      where: { id: templateId },
      data: {
        name: updates.name,
        description: updates.description,
        environment: updates.environment,
        config: updates.config as Prisma.InputJsonValue | undefined,
        hash: updates.hash,
        version: updates.version,
        isActive: updates.isActive,
      },
    });

    return this.mapTemplate(updated);
  }

  /**
   * Delete a configuration template
   */
  async deleteTemplate(templateId: string): Promise<void> {
    this.logger.info({ templateId }, 'Deleting config template');

    await this.prisma.configTemplate.delete({
      where: { id: templateId },
    });
  }

  // =============================================================================
  // Config Sync Tracking
  // =============================================================================

  /**
   * Get sync status for a specific sensor
   */
  async getSyncStatus(sensorId: string): Promise<ConfigSyncState> {
    const syncState = await this.prisma.sensorSyncState.findUnique({
      where: { sensorId },
    });

    if (!syncState) {
      // Return default state if not found
      return {
        sensorId,
        configInSync: false,
        rulesInSync: false,
        blocklistInSync: false,
        syncErrors: [],
      };
    }

    return {
      sensorId: syncState.sensorId,
      configInSync: syncState.expectedConfigHash === syncState.actualConfigHash,
      rulesInSync: syncState.expectedRulesHash === syncState.actualRulesHash,
      blocklistInSync: syncState.expectedBlocklistHash === syncState.actualBlocklistHash,
      lastSyncAttempt: syncState.lastSyncAttempt ?? undefined,
      lastSyncSuccess: syncState.lastSyncSuccess ?? undefined,
      syncErrors: syncState.syncErrors,
    };
  }

  /**
   * Get fleet-wide sync status
   */
  async getFleetSyncStatus(): Promise<FleetSyncStatus> {
    const sensors = await this.prisma.sensor.findMany({
      include: {
        syncState: true,
      },
    });

    let syncedCount = 0;
    let outOfSyncCount = 0;
    let errorCount = 0;

    for (const sensor of sensors) {
      if (!sensor.syncState) {
        outOfSyncCount++;
        continue;
      }

      const configInSync = sensor.syncState.expectedConfigHash === sensor.syncState.actualConfigHash;
      const rulesInSync = sensor.syncState.expectedRulesHash === sensor.syncState.actualRulesHash;
      const blocklistInSync = sensor.syncState.expectedBlocklistHash === sensor.syncState.actualBlocklistHash;

      const fullyInSync = configInSync && rulesInSync && blocklistInSync;

      if (sensor.syncState.syncErrors.length > 0) {
        errorCount++;
      } else if (fullyInSync) {
        syncedCount++;
      } else {
        outOfSyncCount++;
      }
    }

    const totalSensors = sensors.length;
    const syncPercentage = totalSensors > 0 ? (syncedCount / totalSensors) * 100 : 0;

    return {
      totalSensors,
      syncedSensors: syncedCount,
      outOfSyncSensors: outOfSyncCount,
      errorSensors: errorCount,
      syncPercentage: Math.round(syncPercentage * 100) / 100,
    };
  }

  /**
   * Get list of sensors that are out of sync
   */
  async getSensorsOutOfSync(): Promise<string[]> {
    const sensors = await this.prisma.sensor.findMany({
      include: {
        syncState: true,
      },
    });

    const outOfSync: string[] = [];

    for (const sensor of sensors) {
      if (!sensor.syncState) {
        outOfSync.push(sensor.id);
        continue;
      }

      const configInSync = sensor.syncState.expectedConfigHash === sensor.syncState.actualConfigHash;
      const rulesInSync = sensor.syncState.expectedRulesHash === sensor.syncState.actualRulesHash;
      const blocklistInSync = sensor.syncState.expectedBlocklistHash === sensor.syncState.actualBlocklistHash;

      if (!configInSync || !rulesInSync || !blocklistInSync) {
        outOfSync.push(sensor.id);
      }
    }

    return outOfSync;
  }

  /**
   * Update sync state for a sensor
   */
  async updateSyncState(
    sensorId: string,
    updates: {
      expectedConfigHash?: string;
      expectedRulesHash?: string;
      expectedBlocklistHash?: string;
      actualConfigHash?: string;
      actualRulesHash?: string;
      actualBlocklistHash?: string;
      lastSyncAttempt?: Date;
      lastSyncSuccess?: Date;
      syncErrors?: string[];
    }
  ): Promise<void> {
    await this.prisma.sensorSyncState.upsert({
      where: { sensorId },
      create: {
        sensorId,
        expectedConfigHash: updates.expectedConfigHash ?? '',
        expectedRulesHash: updates.expectedRulesHash ?? '',
        expectedBlocklistHash: updates.expectedBlocklistHash ?? '',
        actualConfigHash: updates.actualConfigHash,
        actualRulesHash: updates.actualRulesHash,
        actualBlocklistHash: updates.actualBlocklistHash,
        lastSyncAttempt: updates.lastSyncAttempt,
        lastSyncSuccess: updates.lastSyncSuccess,
        syncErrors: updates.syncErrors ?? [],
      },
      update: {
        expectedConfigHash: updates.expectedConfigHash,
        expectedRulesHash: updates.expectedRulesHash,
        expectedBlocklistHash: updates.expectedBlocklistHash,
        actualConfigHash: updates.actualConfigHash,
        actualRulesHash: updates.actualRulesHash,
        actualBlocklistHash: updates.actualBlocklistHash,
        lastSyncAttempt: updates.lastSyncAttempt,
        lastSyncSuccess: updates.lastSyncSuccess,
        syncErrors: updates.syncErrors,
      },
    });
  }

  // =============================================================================
  // Config Operations
  // =============================================================================

  /**
   * Generate config diff between current sensor config and target template
   */
  async generateConfigDiff(sensorId: string, templateId: string): Promise<ConfigDiff> {
    const template = await this.getTemplate(templateId);
    if (!template) {
      throw new Error(`Template ${templateId} not found`);
    }

    // Get current sensor sync state to retrieve actual config
    const syncState = await this.prisma.sensorSyncState.findUnique({
      where: { sensorId },
    });

    // For now, we'll return a simple diff
    // In a real implementation, you'd fetch the actual config from the sensor
    const currentConfig = syncState ? null : null; // Placeholder
    const targetConfig = template.config;

    const differences = this.computeDifferences(currentConfig, targetConfig);

    return {
      sensorId,
      currentConfig,
      targetConfig,
      differences,
    };
  }

  /**
   * Push configuration to sensors
   */
  async pushConfig(sensorIds: string[], templateId: string): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      throw new Error('FleetCommander not initialized');
    }

    const template = await this.getTemplate(templateId);
    if (!template) {
      throw new Error(`Template ${templateId} not found`);
    }

    this.logger.info({ sensorIds, templateId }, 'Pushing config to sensors');

    // Send push_config command to each sensor
    const commandIds = await this.fleetCommander.sendCommandToMultiple(sensorIds, {
      type: 'push_config',
      payload: {
        templateId,
        config: template.config,
        hash: template.hash,
        version: template.version,
      },
    });

    // Update expected config hash for each sensor
    for (const sensorId of sensorIds) {
      await this.updateSyncState(sensorId, {
        expectedConfigHash: template.hash,
        lastSyncAttempt: new Date(),
      });
    }

    // Track deployment results
    const results: DeploymentResult['results'] = [];
    let successCount = 0;
    let failureCount = 0;
    let pendingCount = sensorIds.length;

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
      successCount,
      failureCount,
      pendingCount,
      results,
    };
  }

  /**
   * Compute configuration hash (SHA-256)
   */
  async computeConfigHash(config: Record<string, unknown>): Promise<string> {
    const configString = JSON.stringify(config, Object.keys(config).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(configString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // =============================================================================
  // Private Helpers
  // =============================================================================

  private mapTemplate(template: {
    id: string;
    name: string;
    description: string | null;
    environment: string;
    config: unknown;
    hash: string;
    version: string;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
  }): ConfigTemplate {
    return {
      id: template.id,
      name: template.name,
      description: template.description ?? undefined,
      environment: template.environment as 'production' | 'staging' | 'dev',
      config: template.config as Record<string, unknown>,
      hash: template.hash,
      version: template.version,
      isActive: template.isActive,
      createdAt: template.createdAt,
      updatedAt: template.updatedAt,
    };
  }

  private computeDifferences(
    current: Record<string, unknown> | null,
    target: Record<string, unknown>
  ): ConfigDiff['differences'] {
    const differences: ConfigDiff['differences'] = [];

    if (!current) {
      // All target keys are additions
      for (const key of Object.keys(target)) {
        differences.push({
          path: key,
          current: undefined,
          target: target[key],
          action: 'add',
        });
      }
      return differences;
    }

    // Find modifications and deletions
    for (const key of Object.keys(current)) {
      if (!(key in target)) {
        differences.push({
          path: key,
          current: current[key],
          target: undefined,
          action: 'remove',
        });
      } else if (JSON.stringify(current[key]) !== JSON.stringify(target[key])) {
        differences.push({
          path: key,
          current: current[key],
          target: target[key],
          action: 'modify',
        });
      }
    }

    // Find additions
    for (const key of Object.keys(target)) {
      if (!(key in current)) {
        differences.push({
          path: key,
          current: undefined,
          target: target[key],
          action: 'add',
        });
      }
    }

    return differences;
  }
}
