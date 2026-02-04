import type { Request } from 'express';
import { PrismaClient } from '@prisma/client';
import { Logger } from 'pino';
import { FleetCommander } from './fleet/fleet-commander.js';
import { SensorConfig, SensorConfigSchema } from '../schemas/sensorConfig.js';
import {
  encryptSensitiveFields,
  decryptSensitiveFields,
  hasEncryptedFields,
} from '../lib/crypto.js';
import { createApiError } from '../lib/errors.js';
import { SecurityAuditService } from './audit/security-audit.js';

export class SensorConfigService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger,
    private fleetCommander: FleetCommander,
    private auditService?: SecurityAuditService
  ) {}

  private toAuditConfigSnapshot(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return {};
    }

    const rawConfig = value as Record<string, unknown>;
    if (hasEncryptedFields(rawConfig)) {
      return decryptSensitiveFields(rawConfig) as Record<string, unknown>;
    }

    return rawConfig;
  }

  /**
   * Get configuration for a sensor.
   * Returns null if no config exists.
   *
   * Security: Decrypts sensitive fields that were encrypted at rest.
   */
  async getConfig(sensorId: string): Promise<SensorConfig | null> {
    const record = await this.prisma.sensorPingoraConfig.findUnique({
      where: { sensorId },
    });

    if (!record || !record.fullConfig) {
      return null;
    }

    const rawConfig = record.fullConfig as Record<string, unknown>;

    // Check if config has encrypted fields (new format) or is plaintext (legacy)
    if (hasEncryptedFields(rawConfig)) {
      // Decrypt sensitive fields
      const decrypted = decryptSensitiveFields(rawConfig);
      return decrypted as unknown as SensorConfig;
    }

    // Legacy plaintext config - return as-is (will be encrypted on next update)
    this.logger.warn(
      { sensorId },
      'Config contains plaintext sensitive data. Will be encrypted on next update.'
    );
    return rawConfig as unknown as SensorConfig;
  }

  /**
   * Update configuration for a sensor and push to device.
   *
   * Security: Encrypts sensitive fields before storing in database.
   */
  async updateConfig(
    req: Request,
    sensorId: string,
    config: SensorConfig,
    tenantId: string
  ): Promise<{ version: number, commandId?: string }> {
    // Validate config structure
    const validatedConfig = SensorConfigSchema.parse(config);

    // Update DB
    const sensor = await this.prisma.sensor.findUnique({
      where: { id: sensorId },
      include: { pingoraConfig: true },
    });

    if (!sensor) {
      throw createApiError('NOT_FOUND', {
        message: `Sensor ${sensorId} not found`,
        context: { sensorId },
      });
    }

    if (sensor.tenantId !== tenantId) {
      throw createApiError('PERMISSION_DENIED', {
        message: `Sensor ${sensorId} does not belong to tenant ${tenantId}`,
        context: { sensorId, tenantId },
      });
    }

    const previousConfig = this.toAuditConfigSnapshot(sensor.pingoraConfig?.fullConfig);
    const hadExistingConfig = Boolean(sensor.pingoraConfig?.fullConfig);
    const currentVersion = sensor.pingoraConfig?.version || 0;
    const newVersion = currentVersion + 1;

    // SECURITY: Encrypt sensitive configuration fields before storing
    // Fields matching patterns like *Secret, *Key, *Password, hmac*, tls*, private* are encrypted
    const encryptedConfig = encryptSensitiveFields(validatedConfig as unknown as Record<string, unknown>);

    await this.prisma.sensorPingoraConfig.upsert({
      where: { sensorId },
      create: {
        sensorId,
        fullConfig: encryptedConfig as any,
        version: newVersion,
        // Populate legacy fields for backward compatibility
        wafEnabled: validatedConfig.server.waf_enabled,
        wafThreshold: validatedConfig.server.waf_threshold / 100.0,
        rateLimitEnabled: validatedConfig.rate_limit.enabled,
        rps: validatedConfig.rate_limit.rps,
        allowList: [],
        denyList: [],
      },
      update: {
        fullConfig: encryptedConfig as any,
        version: newVersion,
        // Sync legacy fields
        wafEnabled: validatedConfig.server.waf_enabled,
        wafThreshold: validatedConfig.server.waf_threshold / 100.0,
        rateLimitEnabled: validatedConfig.rate_limit.enabled,
        rps: validatedConfig.rate_limit.rps,
      },
    });

    if (this.auditService) {
      const auditValues = validatedConfig as unknown as Record<string, unknown>;
      if (hadExistingConfig) {
        void this.auditService.logConfigUpdated(
          req,
          'sensor_config',
          sensorId,
          previousConfig,
          auditValues
        );
      } else {
        void this.auditService.logConfigCreated(
          req,
          'sensor_config',
          sensorId,
          auditValues
        );
      }
    }

    this.logger.info({ sensorId, version: newVersion }, 'Sensor configuration updated');

    // Push to sensor via FleetCommander
    // This handles persistence of the command and delivery
    const commandId = await this.fleetCommander.sendCommand(tenantId, sensorId, {
      type: 'push_config',
      payload: {
        config: validatedConfig,
        version: newVersion.toString(),
      },
    });

    return { version: newVersion, commandId };
  }
}
