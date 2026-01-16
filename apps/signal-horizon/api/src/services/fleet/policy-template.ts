/**
 * Policy Template Service
 * Manage global security policy templates with tenant isolation
 */

import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'node:crypto';
import type {
  PolicyTemplate,
  PolicyConfig,
  PolicySeverity,
  CreatePolicyTemplateInput,
  UpdatePolicyTemplateInput,
  ApplyPolicyTemplateInput,
  PolicyApplicationResult,
  PolicyTemplateMetadata,
} from './policy-template-types.js';
import { createDefaultTemplates, getDefaultPolicyConfig } from './default-policies.js';
import type { RolloutConfig, RolloutStrategy, DeploymentResult } from './types.js';
import type { FleetCommander } from './fleet-commander.js';

/**
 * Error thrown when a tenant attempts to access resources they don't own
 */
export class PolicyAccessError extends Error {
  constructor(
    public readonly tenantId: string,
    public readonly resourceId: string,
    public readonly resourceType: string
  ) {
    super(`Tenant ${tenantId} does not have access to ${resourceType}: ${resourceId}`);
    this.name = 'PolicyAccessError';
  }
}

/**
 * Error thrown when a policy template is not found
 */
export class PolicyNotFoundError extends Error {
  constructor(public readonly templateId: string) {
    super(`Policy template not found: ${templateId}`);
    this.name = 'PolicyNotFoundError';
  }
}

/**
 * Error thrown when attempting to modify a default template
 */
export class DefaultTemplateModificationError extends Error {
  constructor(public readonly templateId: string) {
    super(`Cannot modify default policy template: ${templateId}`);
    this.name = 'DefaultTemplateModificationError';
  }
}

/**
 * Policy Template Service
 * Manages security policy templates with CRUD operations and deployment
 */
export class PolicyTemplateService {
  private prisma: PrismaClient;
  private logger: Logger;
  private fleetCommander: FleetCommander | null = null;

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'policy-template' });
  }

  /**
   * Set fleet commander for policy deployment
   * This is set after construction to avoid circular dependency
   */
  setFleetCommander(commander: FleetCommander): void {
    this.fleetCommander = commander;
  }

  // =============================================================================
  // CRUD Operations
  // =============================================================================

  /**
   * List all policy templates for a tenant
   */
  async listTemplates(tenantId: string): Promise<PolicyTemplate[]> {
    const templates = await this.prisma.policyTemplate.findMany({
      where: { tenantId },
      orderBy: [
        { isDefault: 'desc' },
        { severity: 'asc' },
        { name: 'asc' },
      ],
    });

    return templates.map((t) => this.mapDbToTemplate(t));
  }

  /**
   * Get a single policy template by ID
   */
  async getTemplate(tenantId: string, templateId: string): Promise<PolicyTemplate | null> {
    const template = await this.prisma.policyTemplate.findUnique({
      where: { id: templateId },
    });

    if (!template) {
      return null;
    }

    // Verify tenant ownership
    if (template.tenantId !== tenantId) {
      throw new PolicyAccessError(tenantId, templateId, 'policy template');
    }

    return this.mapDbToTemplate(template);
  }

  /**
   * Get default policy templates (Strict, Standard, Dev)
   * These are system-provided templates available to all tenants
   */
  async getDefaultTemplates(tenantId: string): Promise<PolicyTemplate[]> {
    // Check if default templates exist for this tenant
    const existingDefaults = await this.prisma.policyTemplate.findMany({
      where: {
        tenantId,
        isDefault: true,
      },
    });

    // If no defaults exist, create them
    if (existingDefaults.length === 0) {
      await this.seedDefaultTemplates(tenantId);
      const defaults = await this.prisma.policyTemplate.findMany({
        where: {
          tenantId,
          isDefault: true,
        },
        orderBy: { severity: 'asc' },
      });
      return defaults.map((t) => this.mapDbToTemplate(t));
    }

    return existingDefaults.map((t) => this.mapDbToTemplate(t));
  }

  /**
   * Create a custom policy template
   */
  async createTemplate(
    tenantId: string,
    input: CreatePolicyTemplateInput
  ): Promise<PolicyTemplate> {
    const id = randomUUID();
    const now = new Date();

    const metadata: PolicyTemplateMetadata = input.metadata ?? {
      category: 'custom',
    };

    const template = await this.prisma.policyTemplate.create({
      data: {
        id,
        tenantId,
        name: input.name,
        description: input.description ?? null,
        severity: input.severity,
        config: input.config as unknown as Prisma.InputJsonValue,
        metadata: metadata as unknown as Prisma.InputJsonValue,
        isDefault: false,
        isActive: true,
        version: '1.0.0',
        createdAt: now,
        updatedAt: now,
      },
    });

    this.logger.info(
      { templateId: id, tenantId, name: input.name },
      'Created policy template'
    );

    return this.mapDbToTemplate(template);
  }

  /**
   * Update a policy template
   * Note: Default templates cannot be modified
   */
  async updateTemplate(
    tenantId: string,
    templateId: string,
    input: UpdatePolicyTemplateInput
  ): Promise<PolicyTemplate> {
    // Get existing template
    const existing = await this.prisma.policyTemplate.findUnique({
      where: { id: templateId },
    });

    if (!existing) {
      throw new PolicyNotFoundError(templateId);
    }

    // Verify tenant ownership
    if (existing.tenantId !== tenantId) {
      throw new PolicyAccessError(tenantId, templateId, 'policy template');
    }

    // Prevent modification of default templates
    if (existing.isDefault) {
      throw new DefaultTemplateModificationError(templateId);
    }

    // Increment version if config changes
    let newVersion = existing.version;
    if (input.config) {
      const versionParts = existing.version.split('.');
      const patch = parseInt(versionParts[2] || '0', 10) + 1;
      newVersion = `${versionParts[0]}.${versionParts[1]}.${patch}`;
    }

    const updated = await this.prisma.policyTemplate.update({
      where: { id: templateId },
      data: {
        name: input.name ?? existing.name,
        description: input.description ?? existing.description,
        severity: input.severity ?? existing.severity,
        config: input.config
          ? (input.config as unknown as Prisma.InputJsonValue)
          : (existing.config as Prisma.InputJsonValue),
        metadata: input.metadata
          ? (input.metadata as unknown as Prisma.InputJsonValue)
          : (existing.metadata as Prisma.InputJsonValue ?? undefined),
        version: newVersion,
        updatedAt: new Date(),
      },
    });

    this.logger.info(
      { templateId, tenantId, version: newVersion },
      'Updated policy template'
    );

    return this.mapDbToTemplate(updated);
  }

  /**
   * Delete a policy template
   * Note: Default templates cannot be deleted
   */
  async deleteTemplate(tenantId: string, templateId: string): Promise<void> {
    // Get existing template
    const existing = await this.prisma.policyTemplate.findUnique({
      where: { id: templateId },
    });

    if (!existing) {
      throw new PolicyNotFoundError(templateId);
    }

    // Verify tenant ownership
    if (existing.tenantId !== tenantId) {
      throw new PolicyAccessError(tenantId, templateId, 'policy template');
    }

    // Prevent deletion of default templates
    if (existing.isDefault) {
      throw new DefaultTemplateModificationError(templateId);
    }

    await this.prisma.policyTemplate.delete({
      where: { id: templateId },
    });

    this.logger.info(
      { templateId, tenantId },
      'Deleted policy template'
    );
  }

  // =============================================================================
  // Policy Application
  // =============================================================================

  /**
   * Apply a policy template to sensors with rollout strategy
   */
  async applyTemplate(
    tenantId: string,
    templateId: string,
    input: ApplyPolicyTemplateInput
  ): Promise<PolicyApplicationResult> {
    const startedAt = new Date();

    // Get template
    const template = await this.getTemplate(tenantId, templateId);
    if (!template) {
      throw new PolicyNotFoundError(templateId);
    }

    // Validate sensor ownership
    const sensors = await this.prisma.sensor.findMany({
      where: {
        id: { in: input.sensorIds },
        tenantId,
      },
      select: { id: true },
    });

    const validSensorIds = sensors.map((s) => s.id);
    const invalidSensorIds = input.sensorIds.filter((id) => !validSensorIds.includes(id));

    if (invalidSensorIds.length > 0) {
      this.logger.warn(
        { tenantId, invalidSensorIds },
        'Some sensors not found or not owned by tenant'
      );
    }

    if (validSensorIds.length === 0) {
      return {
        success: false,
        templateId,
        appliedTo: [],
        failed: invalidSensorIds.map((id) => ({
          sensorId: id,
          error: 'Sensor not found or not owned by tenant',
        })),
        strategy: input.strategy,
        startedAt,
        completedAt: new Date(),
      };
    }

    // Check if fleet commander is available
    if (!this.fleetCommander) {
      this.logger.warn('Fleet commander not available for policy deployment');
      return {
        success: false,
        templateId,
        appliedTo: [],
        failed: validSensorIds.map((id) => ({
          sensorId: id,
          error: 'Fleet commander service not available',
        })),
        strategy: input.strategy,
        startedAt,
        completedAt: new Date(),
      };
    }

    // Build rollout config
    const rolloutConfig: RolloutConfig = {
      strategy: input.strategy as RolloutStrategy,
      canaryPercentages: input.canaryPercentage ? [input.canaryPercentage, 50, 100] : undefined,
      scheduledTime: input.scheduledTime ? new Date(input.scheduledTime) : undefined,
      rollingBatchSize: input.rollingBatchSize,
      healthCheckTimeout: input.healthCheckTimeout,
      maxFailuresBeforeAbort: input.maxFailuresBeforeAbort,
      rollbackOnFailure: input.rollbackOnFailure,
      healthCheckIntervalMs: input.healthCheckIntervalMs,
      stagingTimeout: input.stagingTimeout,
      switchTimeout: input.switchTimeout,
      requireAllSensorsStaged: input.requireAllSensorsStaged,
      minStagedPercentage: input.minStagedPercentage,
      cleanupDelayMs: input.cleanupDelayMs,
    };

    // Deploy policy to sensors via push_config command
    const results: DeploymentResult = await this.deployPolicyToSensors(
      validSensorIds,
      template,
      rolloutConfig
    );

    const failed = results.results
      .filter((r) => !r.success)
      .map((r) => ({ sensorId: r.sensorId, error: r.error ?? 'Unknown error' }));

    // Add invalid sensor IDs to failed list
    failed.push(
      ...invalidSensorIds.map((id) => ({
        sensorId: id,
        error: 'Sensor not found or not owned by tenant',
      }))
    );

    const appliedTo = results.results
      .filter((r) => r.success)
      .map((r) => r.sensorId);

    return {
      success: results.success,
      templateId,
      appliedTo,
      failed,
      strategy: input.strategy,
      deploymentId: results.scheduledDeploymentId,
      startedAt,
      completedAt: new Date(),
    };
  }

  // =============================================================================
  // Private Helpers
  // =============================================================================

  /**
   * Deploy policy configuration to sensors
   */
  private async deployPolicyToSensors(
    sensorIds: string[],
    template: PolicyTemplate,
    rolloutConfig: RolloutConfig
  ): Promise<DeploymentResult> {
    if (!this.fleetCommander) {
      return {
        success: false,
        totalTargets: sensorIds.length,
        successCount: 0,
        failureCount: sensorIds.length,
        pendingCount: 0,
        results: sensorIds.map((id) => ({
          sensorId: id,
          success: false,
          error: 'Fleet commander not available',
        })),
      };
    }

    const results: Array<{ sensorId: string; success: boolean; error?: string; commandId?: string }> = [];

    // For immediate strategy, send commands to all sensors
    if (rolloutConfig.strategy === 'immediate') {
      for (const sensorId of sensorIds) {
        try {
          const commandId = await this.fleetCommander.sendCommand(sensorId, {
            type: 'push_config',
            payload: {
              policyTemplateId: template.id,
              policyName: template.name,
              policySeverity: template.severity,
              config: template.config,
              version: template.version,
            },
          });

          results.push({
            sensorId,
            success: true,
            commandId,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          results.push({
            sensorId,
            success: false,
            error: message,
          });
        }
      }
    } else {
      // For other strategies, we'd need to implement batch/staged deployment
      // For now, treat as immediate but log the intended strategy
      this.logger.info(
        { strategy: rolloutConfig.strategy, sensorCount: sensorIds.length },
        'Applying policy with strategy (falling back to immediate for now)'
      );

      for (const sensorId of sensorIds) {
        try {
          const commandId = await this.fleetCommander.sendCommand(sensorId, {
            type: 'push_config',
            payload: {
              policyTemplateId: template.id,
              policyName: template.name,
              policySeverity: template.severity,
              config: template.config,
              version: template.version,
              rolloutStrategy: rolloutConfig.strategy,
            },
          });

          results.push({
            sensorId,
            success: true,
            commandId,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          results.push({
            sensorId,
            success: false,
            error: message,
          });
        }
      }
    }

    const successCount = results.filter((r) => r.success).length;
    const failureCount = results.filter((r) => !r.success).length;

    return {
      success: failureCount === 0,
      totalTargets: sensorIds.length,
      successCount,
      failureCount,
      pendingCount: 0,
      results,
    };
  }

  /**
   * Seed default templates for a tenant
   */
  private async seedDefaultTemplates(tenantId: string): Promise<void> {
    const defaults = createDefaultTemplates(tenantId);
    const now = new Date();

    for (const template of defaults) {
      const id = randomUUID();
      await this.prisma.policyTemplate.create({
        data: {
          id,
          tenantId: template.tenantId,
          name: template.name,
          description: template.description ?? null,
          severity: template.severity,
          config: template.config as unknown as Prisma.InputJsonValue,
          metadata: template.metadata as unknown as Prisma.InputJsonValue,
          isDefault: template.isDefault,
          isActive: template.isActive,
          version: template.version,
          createdAt: now,
          updatedAt: now,
        },
      });
    }

    this.logger.info(
      { tenantId, count: defaults.length },
      'Seeded default policy templates'
    );
  }

  /**
   * Map database record to PolicyTemplate type
   */
  private mapDbToTemplate(record: {
    id: string;
    tenantId: string;
    name: string;
    description: string | null;
    severity: string;
    config: Prisma.JsonValue;
    metadata: Prisma.JsonValue;
    isDefault: boolean;
    isActive: boolean;
    version: string;
    createdAt: Date;
    updatedAt: Date;
  }): PolicyTemplate {
    return {
      id: record.id,
      tenantId: record.tenantId,
      name: record.name,
      description: record.description ?? undefined,
      severity: record.severity as PolicySeverity,
      config: record.config as unknown as PolicyConfig,
      metadata: record.metadata as unknown as PolicyTemplateMetadata,
      isDefault: record.isDefault,
      isActive: record.isActive,
      version: record.version,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  /**
   * Clone an existing template with a new name
   */
  async cloneTemplate(
    tenantId: string,
    sourceTemplateId: string,
    newName: string
  ): Promise<PolicyTemplate> {
    const source = await this.getTemplate(tenantId, sourceTemplateId);
    if (!source) {
      throw new PolicyNotFoundError(sourceTemplateId);
    }

    return this.createTemplate(tenantId, {
      name: newName,
      description: `Cloned from: ${source.name}`,
      severity: source.severity,
      config: source.config,
      metadata: {
        ...source.metadata,
        category: 'custom',
      },
    });
  }

  /**
   * Get policy config by severity (utility for quick access)
   */
  getDefaultConfigBySeverity(severity: PolicySeverity): PolicyConfig {
    return getDefaultPolicyConfig(severity);
  }
}
