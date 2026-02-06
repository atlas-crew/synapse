import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { PrismaClient, Playbook, WarRoom, PlaybookRun } from '@prisma/client';
import type { Logger } from 'pino';
import type { EnrichedSignal, Severity } from '../../../types/protocol.js';
import { AutomatedPlaybookTrigger, type AutomatedTriggerConfig } from '../automated-trigger.js';
import { PlaybookService, PlaybookConcurrencyError } from '../playbook-service.js';

// Mock PrismaClient
const createMockPrisma = () => ({
  playbook: {
    findMany: vi.fn(),
  },
  warRoom: {
    findFirst: vi.fn(),
    create: vi.fn(),
  },
});

// Mock Logger
const createMockLogger = () => ({
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
});

// Mock PlaybookService
const createMockPlaybookService = () => ({
  runPlaybook: vi.fn(),
  createPlaybook: vi.fn(),
  listPlaybooks: vi.fn(),
  executeStep: vi.fn(),
  cancelPlaybookRun: vi.fn(),
  countActiveRunsForTenant: vi.fn(),
  hasActiveRunInWarRoom: vi.fn(),
});

// Helper to create a mock enriched signal
const createMockSignal = (overrides: Partial<EnrichedSignal> = {}): EnrichedSignal => ({
  signalType: 'CREDENTIAL_STUFFING',
  severity: 'HIGH' as Severity,
  confidence: 0.9,
  tenantId: 'tenant-1',
  sensorId: 'sensor-1',
  eventCount: 1,
  ...overrides,
});

// Helper to create a mock playbook
const createMockPlaybook = (overrides: Partial<Playbook> = {}): Playbook => ({
  id: 'playbook-1',
  tenantId: 'tenant-1',
  name: 'Test Playbook',
  description: 'Test description',
  triggerType: 'SIGNAL_SEVERITY',
  triggerValue: 'HIGH',
  steps: [],
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

// Helper to create a mock war room
const createMockWarRoom = (overrides: Partial<WarRoom> = {}): WarRoom => ({
  id: 'warroom-1',
  tenantId: 'tenant-1',
  name: 'Test War Room',
  description: 'Test description',
  status: 'ACTIVE',
  priority: 'HIGH',
  leaderId: null,
  closedAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

// Helper to create a mock playbook run
const createMockPlaybookRun = (overrides: Partial<PlaybookRun> = {}): PlaybookRun => ({
  id: 'run-1',
  playbookId: 'playbook-1',
  warRoomId: 'warroom-1',
  tenantId: 'tenant-1',
  status: 'RUNNING',
  currentStep: 0,
  stepResults: [],
  startedBy: 'system',
  startedAt: new Date(),
  completedAt: null,
  ...overrides,
});

describe('AutomatedPlaybookTrigger', () => {
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockLogger: ReturnType<typeof createMockLogger>;
  let mockPlaybookService: ReturnType<typeof createMockPlaybookService>;
  let trigger: AutomatedPlaybookTrigger;
  let testConfig: Partial<AutomatedTriggerConfig>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockPrisma = createMockPrisma();
    mockLogger = createMockLogger();
    mockPlaybookService = createMockPlaybookService();
    testConfig = {
      enabled: true,
      cooldownMs: 60_000,
      maxAutoTriggersPerMinute: 10,
      systemUser: {
        userId: 'system-test',
        userName: 'Test System',
      },
    };

    trigger = new AutomatedPlaybookTrigger(
      mockPrisma as unknown as PrismaClient,
      mockLogger as unknown as Logger,
      mockPlaybookService as unknown as PlaybookService,
      testConfig
    );
  });

  afterEach(() => {
    trigger.stop();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('evaluateSignals', () => {
    it('should do nothing when disabled', async () => {
      trigger.stop();
      trigger = new AutomatedPlaybookTrigger(
        mockPrisma as unknown as PrismaClient,
        mockLogger as unknown as Logger,
        mockPlaybookService as unknown as PlaybookService,
        { ...testConfig, enabled: false }
      );

      const signals = [createMockSignal()];
      await trigger.evaluateSignals(signals);

      expect(mockPrisma.playbook.findMany).not.toHaveBeenCalled();
    });

    it('should do nothing for empty signal array', async () => {
      await trigger.evaluateSignals([]);

      expect(mockPrisma.playbook.findMany).not.toHaveBeenCalled();
    });

    it('should query playbooks for each tenant', async () => {
      const signals = [
        createMockSignal({ tenantId: 'tenant-1' }),
        createMockSignal({ tenantId: 'tenant-2' }),
      ];

      mockPrisma.playbook.findMany.mockResolvedValue([]);

      await trigger.evaluateSignals(signals);

      expect(mockPrisma.playbook.findMany).toHaveBeenCalledTimes(2);
      expect(mockPrisma.playbook.findMany).toHaveBeenCalledWith({
        where: {
          tenantId: 'tenant-1',
          isActive: true,
          triggerType: { in: ['SIGNAL_SEVERITY', 'SIGNAL_TYPE'] },
        },
      });
      expect(mockPrisma.playbook.findMany).toHaveBeenCalledWith({
        where: {
          tenantId: 'tenant-2',
          isActive: true,
          triggerType: { in: ['SIGNAL_SEVERITY', 'SIGNAL_TYPE'] },
        },
      });
    });

    it('should trigger playbook when SIGNAL_SEVERITY matches', async () => {
      const signals = [createMockSignal({ severity: 'CRITICAL' })];
      const playbook = createMockPlaybook({
        triggerType: 'SIGNAL_SEVERITY',
        triggerValue: 'HIGH',
      });
      const warRoom = createMockWarRoom();
      const run = createMockPlaybookRun();

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
      mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
      mockPlaybookService.runPlaybook.mockResolvedValue(run);

      await trigger.evaluateSignals(signals);

      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledWith(
        playbook.id,
        warRoom.id,
        'tenant-1',
        testConfig.systemUser
      );
    });

    it('should trigger playbook when SIGNAL_TYPE matches', async () => {
      const signals = [createMockSignal({ signalType: 'CREDENTIAL_STUFFING' })];
      const playbook = createMockPlaybook({
        triggerType: 'SIGNAL_TYPE',
        triggerValue: 'CREDENTIAL_STUFFING',
      });
      const warRoom = createMockWarRoom();
      const run = createMockPlaybookRun();

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
      mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
      mockPlaybookService.runPlaybook.mockResolvedValue(run);

      await trigger.evaluateSignals(signals);

      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledWith(
        playbook.id,
        warRoom.id,
        'tenant-1',
        testConfig.systemUser
      );
    });

    it('should NOT trigger when severity is below threshold', async () => {
      const signals = [createMockSignal({ severity: 'LOW' })];
      const playbook = createMockPlaybook({
        triggerType: 'SIGNAL_SEVERITY',
        triggerValue: 'HIGH',
      });

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);

      await trigger.evaluateSignals(signals);

      expect(mockPrisma.warRoom.findFirst).not.toHaveBeenCalled();
      expect(mockPlaybookService.runPlaybook).not.toHaveBeenCalled();
    });

    it('should NOT trigger when signal type does not match', async () => {
      const signals = [createMockSignal({ signalType: 'BOT_SIGNATURE' })];
      const playbook = createMockPlaybook({
        triggerType: 'SIGNAL_TYPE',
        triggerValue: 'CREDENTIAL_STUFFING',
      });

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);

      await trigger.evaluateSignals(signals);

      expect(mockPrisma.warRoom.findFirst).not.toHaveBeenCalled();
      expect(mockPlaybookService.runPlaybook).not.toHaveBeenCalled();
    });

    it('should create war room when none exists', async () => {
      const signals = [createMockSignal({ severity: 'CRITICAL' })];
      const playbook = createMockPlaybook();
      const newWarRoom = createMockWarRoom();
      const run = createMockPlaybookRun();

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
      mockPrisma.warRoom.findFirst.mockResolvedValue(null);
      mockPrisma.warRoom.create.mockResolvedValue(newWarRoom);
      mockPlaybookService.runPlaybook.mockResolvedValue(run);

      await trigger.evaluateSignals(signals);

      expect(mockPrisma.warRoom.create).toHaveBeenCalled();
      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledWith(
        playbook.id,
        newWarRoom.id,
        'tenant-1',
        testConfig.systemUser
      );
    });
  });

  describe('cooldown', () => {
    it('should respect cooldown period', async () => {
      const signals = [createMockSignal({ severity: 'CRITICAL' })];
      const playbook = createMockPlaybook();
      const warRoom = createMockWarRoom();
      const run = createMockPlaybookRun();

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
      mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
      mockPlaybookService.runPlaybook.mockResolvedValue(run);

      // First trigger should work
      await trigger.evaluateSignals(signals);
      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledTimes(1);

      // Second trigger immediately should be blocked by cooldown
      await trigger.evaluateSignals(signals);
      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledTimes(1);

      // Advance past cooldown
      vi.advanceTimersByTime(testConfig.cooldownMs! + 1000);

      // Third trigger should work again
      await trigger.evaluateSignals(signals);
      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledTimes(2);
    });
  });

  describe('rate limiting', () => {
    it('should enforce rate limit per tenant', async () => {
      const signals = [createMockSignal({ severity: 'CRITICAL' })];
      const warRoom = createMockWarRoom();
      const run = createMockPlaybookRun();

      mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
      mockPlaybookService.runPlaybook.mockResolvedValue(run);

      // Create many playbooks to trigger (more than rate limit)
      const playbooks = Array.from({ length: 15 }, (_, i) =>
        createMockPlaybook({
          id: `playbook-${i}`,
          name: `Playbook ${i}`,
        })
      );
      mockPrisma.playbook.findMany.mockResolvedValue(playbooks);

      // Evaluation should trigger up to rate limit and stop
      await trigger.evaluateSignals(signals);

      // Should have triggered exactly maxAutoTriggersPerMinute times
      expect(mockPlaybookService.runPlaybook).toHaveBeenCalledTimes(
        testConfig.maxAutoTriggersPerMinute!
      );

      // Should have logged rate limit warning for subsequent triggers
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ tenantId: 'tenant-1' }),
        'Rate limit exceeded for automated playbook triggers'
      );
    });
  });

  describe('concurrency handling', () => {
    it('should handle PlaybookConcurrencyError gracefully', async () => {
      const signals = [createMockSignal({ severity: 'CRITICAL' })];
      const playbook = createMockPlaybook();
      const warRoom = createMockWarRoom();

      mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
      mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
      mockPlaybookService.runPlaybook.mockRejectedValue(
        new PlaybookConcurrencyError('Already running')
      );

      // Should not throw
      await expect(trigger.evaluateSignals(signals)).resolves.not.toThrow();

      // Should log debug message
      expect(mockLogger.debug).toHaveBeenCalledWith(
        expect.objectContaining({ playbookId: playbook.id }),
        'Playbook already running in war room'
      );
    });
  });

  describe('severity threshold matching', () => {
    it.each([
      { target: 'LOW', signal: 'LOW', shouldMatch: true },
      { target: 'LOW', signal: 'MEDIUM', shouldMatch: true },
      { target: 'LOW', signal: 'HIGH', shouldMatch: true },
      { target: 'LOW', signal: 'CRITICAL', shouldMatch: true },
      { target: 'MEDIUM', signal: 'LOW', shouldMatch: false },
      { target: 'MEDIUM', signal: 'MEDIUM', shouldMatch: true },
      { target: 'MEDIUM', signal: 'HIGH', shouldMatch: true },
      { target: 'HIGH', signal: 'LOW', shouldMatch: false },
      { target: 'HIGH', signal: 'MEDIUM', shouldMatch: false },
      { target: 'HIGH', signal: 'HIGH', shouldMatch: true },
      { target: 'CRITICAL', signal: 'HIGH', shouldMatch: false },
      { target: 'CRITICAL', signal: 'CRITICAL', shouldMatch: true },
    ])(
      'target $target should %s match signal $signal',
      async ({ target, signal, shouldMatch }) => {
        const signals = [createMockSignal({ severity: signal as Severity })];
        const playbook = createMockPlaybook({
          triggerType: 'SIGNAL_SEVERITY',
          triggerValue: target,
        });
        const warRoom = createMockWarRoom();
        const run = createMockPlaybookRun();

        mockPrisma.playbook.findMany.mockResolvedValue([playbook]);
        mockPrisma.warRoom.findFirst.mockResolvedValue(warRoom);
        mockPlaybookService.runPlaybook.mockResolvedValue(run);

        await trigger.evaluateSignals(signals);

        if (shouldMatch) {
          expect(mockPlaybookService.runPlaybook).toHaveBeenCalled();
        } else {
          expect(mockPlaybookService.runPlaybook).not.toHaveBeenCalled();
        }
      }
    );
  });

  describe('stop', () => {
    it('should clean up resources on stop', () => {
      trigger.stop();

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Automated playbook trigger service stopped'
      );
    });
  });
});
