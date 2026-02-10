import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SensorConfigService } from '../sensorConfigService.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Mock crypto module — track calls without doing real encryption
const mockEncrypt = vi.fn().mockImplementation((config) => ({ ...config, _encrypted: true }));
const mockDecrypt = vi.fn().mockImplementation((config) => ({ ...config, _decrypted: true }));
const mockHasEncrypted = vi.fn().mockReturnValue(true);

vi.mock('../../lib/crypto.js', () => ({
  encryptSensitiveFields: (...args: unknown[]) => mockEncrypt(...args),
  decryptSensitiveFields: (...args: unknown[]) => mockDecrypt(...args),
  hasEncryptedFields: (...args: unknown[]) => mockHasEncrypted(...args),
}));

// Mock errors — produce throwable objects with a .code property
vi.mock('../../lib/errors.js', () => ({
  createApiError: (code: string, opts: { message: string; context?: Record<string, unknown> }) => {
    const err = new Error(opts.message);
    (err as any).code = code;
    return err;
  },
}));

// Mock schema validation — reject configs missing a `server` key
vi.mock('../../schemas/sensorConfig.js', () => ({
  SensorConfigSchema: {
    parse: vi.fn().mockImplementation((config: any) => {
      if (!config || !config.server) {
        const err = new Error('ZodError: Invalid config');
        err.name = 'ZodError';
        throw err;
      }
      return config;
    }),
  },
}));

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const TENANT_1 = 'tenant-1';
const TENANT_2 = 'tenant-2';
const SENSOR_1 = 'sensor-1';

const validConfig = {
  server: { waf_enabled: true, waf_threshold: 80 },
  rate_limit: { enabled: true, rps: 100 },
};

const mockPrisma = {
  sensor: {
    findUnique: vi.fn(),
  },
  sensorPingoraConfig: {
    findUnique: vi.fn(),
    upsert: vi.fn(),
  },
} as unknown as PrismaClient;

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

const mockFleetCommander = {
  sendCommand: vi.fn().mockResolvedValue('cmd-1'),
} as any;

const mockAuditService = {
  logConfigCreated: vi.fn(),
  logConfigUpdated: vi.fn(),
} as any;

function createService(audit = true) {
  return new SensorConfigService(
    mockPrisma,
    mockLogger,
    mockFleetCommander,
    audit ? mockAuditService : undefined,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SensorConfigService', () => {
  let service: SensorConfigService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = createService();
  });

  // =========================================================================
  // A5: Tenant isolation
  // =========================================================================
  describe('A5: Tenant isolation', () => {
    // ----- getConfig -----

    it('getConfig returns null when tenantId does not match the sensor owner', async () => {
      // Sensor belongs to TENANT_1, caller passes TENANT_2
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });

      const result = await service.getConfig(SENSOR_1, TENANT_2);

      expect(result).toBeNull();
      // Should NOT attempt to read the config record
      expect(mockPrisma.sensorPingoraConfig.findUnique).not.toHaveBeenCalled();
    });

    it('getConfig returns config when tenantId matches the sensor owner', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });
      (mockPrisma.sensorPingoraConfig.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        sensorId: SENSOR_1,
        fullConfig: { ...validConfig },
        version: 1,
      });

      const result = await service.getConfig(SENSOR_1, TENANT_1);

      expect(result).not.toBeNull();
      expect(mockPrisma.sensorPingoraConfig.findUnique).toHaveBeenCalledWith({
        where: { sensorId: SENSOR_1 },
      });
    });

    it('getConfig returns null for a non-existent sensor', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      const result = await service.getConfig('non-existent', TENANT_1);

      expect(result).toBeNull();
      expect(mockPrisma.sensorPingoraConfig.findUnique).not.toHaveBeenCalled();
    });

    // ----- updateConfig -----

    it('updateConfig throws PERMISSION_DENIED when tenantId does not match', async () => {
      // Sensor exists but belongs to TENANT_1; caller passes TENANT_2
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 1 },
      });

      const mockReq = { auth: { tenantId: TENANT_2 } } as any;

      await expect(
        service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_2),
      ).rejects.toThrow();

      await expect(
        service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_2),
      ).rejects.toMatchObject({ code: 'PERMISSION_DENIED' });

      // Must never write config for wrong tenant
      expect(mockPrisma.sensorPingoraConfig.upsert).not.toHaveBeenCalled();
    });

    it('updateConfig succeeds and returns version when tenantId matches', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 3 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 4,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(result).toHaveProperty('version', 4);
      expect(result).toHaveProperty('commandId', 'cmd-1');
      expect(mockPrisma.sensorPingoraConfig.upsert).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // A6: Encryption roundtrip
  // =========================================================================
  describe('A6: Encryption roundtrip', () => {
    it('updateConfig encrypts sensitive fields before storing', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: null, // no existing config
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 1,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      // encryptSensitiveFields must be called with the validated config
      expect(mockEncrypt).toHaveBeenCalledTimes(1);
      expect(mockEncrypt).toHaveBeenCalledWith(
        expect.objectContaining({ server: validConfig.server }),
      );

      // The encrypted result must be what gets written to the database
      const upsertCall = (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mock
        .calls[0][0];
      expect(upsertCall.create.fullConfig).toHaveProperty('_encrypted', true);
      expect(upsertCall.update.fullConfig).toHaveProperty('_encrypted', true);
    });

    it('getConfig decrypts sensitive fields when reading encrypted config', async () => {
      const encryptedConfig = {
        server: { waf_enabled: true },
        hmacSecret: { _encrypted: true, value: 'cipher-text' },
      };

      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });
      (mockPrisma.sensorPingoraConfig.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        sensorId: SENSOR_1,
        fullConfig: encryptedConfig,
        version: 2,
      });
      mockHasEncrypted.mockReturnValue(true);

      const result = await service.getConfig(SENSOR_1, TENANT_1);

      expect(mockDecrypt).toHaveBeenCalledTimes(1);
      expect(mockDecrypt).toHaveBeenCalledWith(encryptedConfig);
      expect(result).toHaveProperty('_decrypted', true);
    });
  });

  // =========================================================================
  // A7: Config validation
  // =========================================================================
  describe('A7: Config validation', () => {
    it('updateConfig throws ZodError when config is invalid (missing server)', async () => {
      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const invalidConfig = { rate_limit: { enabled: true, rps: 50 } }; // no `server`

      await expect(
        service.updateConfig(mockReq, SENSOR_1, invalidConfig as any, TENANT_1),
      ).rejects.toThrow('ZodError');

      // Must never reach the database write
      expect(mockPrisma.sensor.findUnique).not.toHaveBeenCalled();
      expect(mockPrisma.sensorPingoraConfig.upsert).not.toHaveBeenCalled();
    });

    it('updateConfig succeeds with a valid config', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 1 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 2,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(result).toHaveProperty('version', 2);
      expect(result).toHaveProperty('commandId', 'cmd-1');
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledWith(
        TENANT_1,
        SENSOR_1,
        expect.objectContaining({ type: 'push_config' }),
      );
    });
  });

  // =========================================================================
  // P1: Version increment
  // =========================================================================
  describe('P1: Version increment', () => {
    it('updateConfig increments version from the current value', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 5 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 6,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(result).toHaveProperty('version', 6);

      // Verify the upsert was called with version = currentVersion + 1
      const upsertCall = (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mock
        .calls[0][0];
      expect(upsertCall.create.version).toBe(6);
      expect(upsertCall.update.version).toBe(6);
    });

    it('updateConfig starts at version 1 when no prior config exists', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: null,
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 1,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(result).toHaveProperty('version', 1);

      const upsertCall = (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mock
        .calls[0][0];
      expect(upsertCall.create.version).toBe(1);
      expect(upsertCall.update.version).toBe(1);
    });
  });

  // =========================================================================
  // P1: Command push
  // =========================================================================
  describe('P1: Command push', () => {
    it('updateConfig sends push_config command with config payload and version string', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 2 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 3,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(result).toHaveProperty('commandId', 'cmd-1');
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledWith(
        TENANT_1,
        SENSOR_1,
        {
          type: 'push_config',
          payload: {
            config: validConfig,
            version: '3',
          },
        },
      );
    });
  });

  // =========================================================================
  // P1: Audit logging
  // =========================================================================
  describe('P1: Audit logging', () => {
    it('updateConfig calls logConfigUpdated when sensor already has config', async () => {
      const existingConfig = { server: { waf_enabled: false, waf_threshold: 50 } };
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: existingConfig, version: 1 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 2,
      });
      // Existing config is not encrypted
      mockHasEncrypted.mockReturnValue(false);

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(mockAuditService.logConfigUpdated).toHaveBeenCalledWith(
        mockReq,
        'sensor_config',
        SENSOR_1,
        existingConfig, // previousConfig (plaintext, not encrypted)
        validConfig,    // new config values
      );
      expect(mockAuditService.logConfigCreated).not.toHaveBeenCalled();
    });

    it('updateConfig calls logConfigCreated when sensor has no prior config', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: null,
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 1,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      await service.updateConfig(mockReq, SENSOR_1, validConfig as any, TENANT_1);

      expect(mockAuditService.logConfigCreated).toHaveBeenCalledWith(
        mockReq,
        'sensor_config',
        SENSOR_1,
        validConfig,
      );
      expect(mockAuditService.logConfigUpdated).not.toHaveBeenCalled();
    });

    it('updateConfig does not throw when auditService is not provided', async () => {
      const serviceNoAudit = createService(false);

      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: SENSOR_1,
        tenantId: TENANT_1,
        pingoraConfig: { fullConfig: { server: {} }, version: 1 },
      });
      (mockPrisma.sensorPingoraConfig.upsert as ReturnType<typeof vi.fn>).mockResolvedValue({
        version: 2,
      });

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;
      const result = await serviceNoAudit.updateConfig(
        mockReq,
        SENSOR_1,
        validConfig as any,
        TENANT_1,
      );

      expect(result).toHaveProperty('version', 2);
      expect(mockAuditService.logConfigUpdated).not.toHaveBeenCalled();
      expect(mockAuditService.logConfigCreated).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // P1: Legacy plaintext getConfig
  // =========================================================================
  describe('P1: Legacy plaintext getConfig', () => {
    it('getConfig returns raw config and logs warning when config has no encrypted fields', async () => {
      const plaintextConfig = {
        server: { waf_enabled: true, waf_threshold: 80 },
        hmacSecret: 'plain-secret-value',
      };

      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });
      (mockPrisma.sensorPingoraConfig.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        sensorId: SENSOR_1,
        fullConfig: plaintextConfig,
        version: 1,
      });
      mockHasEncrypted.mockReturnValue(false);

      const result = await service.getConfig(SENSOR_1, TENANT_1);

      // Should return raw config without decryption
      expect(mockDecrypt).not.toHaveBeenCalled();
      expect(result).toEqual(plaintextConfig);

      // Should log a warning about plaintext config
      expect(mockLogger.warn).toHaveBeenCalledWith(
        { sensorId: SENSOR_1 },
        expect.stringContaining('plaintext'),
      );
    });
  });

  // =========================================================================
  // P1: getConfig edge cases
  // =========================================================================
  describe('P1: getConfig edge cases', () => {
    it('getConfig returns null when config record exists but fullConfig is null', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });
      (mockPrisma.sensorPingoraConfig.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        sensorId: SENSOR_1,
        fullConfig: null,
        version: 0,
      });

      const result = await service.getConfig(SENSOR_1, TENANT_1);

      expect(result).toBeNull();
      expect(mockDecrypt).not.toHaveBeenCalled();
    });

    it('getConfig returns null when no config record exists at all', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: TENANT_1,
      });
      (mockPrisma.sensorPingoraConfig.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        null,
      );

      const result = await service.getConfig(SENSOR_1, TENANT_1);

      expect(result).toBeNull();
      expect(mockDecrypt).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // P1: updateConfig error handling
  // =========================================================================
  describe('P1: updateConfig error handling', () => {
    it('updateConfig throws NOT_FOUND for a non-existent sensor', async () => {
      (mockPrisma.sensor.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      const mockReq = { auth: { tenantId: TENANT_1 } } as any;

      await expect(
        service.updateConfig(mockReq, 'non-existent', validConfig as any, TENANT_1),
      ).rejects.toThrow();

      await expect(
        service.updateConfig(mockReq, 'non-existent', validConfig as any, TENANT_1),
      ).rejects.toMatchObject({ code: 'NOT_FOUND' });

      expect(mockPrisma.sensorPingoraConfig.upsert).not.toHaveBeenCalled();
    });

    it('updateConfig rejects an empty config object', async () => {
      const mockReq = { auth: { tenantId: TENANT_1 } } as any;

      await expect(
        service.updateConfig(mockReq, SENSOR_1, {} as any, TENANT_1),
      ).rejects.toThrow('ZodError');

      expect(mockPrisma.sensor.findUnique).not.toHaveBeenCalled();
      expect(mockPrisma.sensorPingoraConfig.upsert).not.toHaveBeenCalled();
    });
  });
});
