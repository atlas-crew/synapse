/**
 * PlaybookService.runPlaybook — P0 Security Tests
 *
 * Covers tenant isolation, concurrency control, and input validation
 * for the playbook execution entry point.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PlaybookService, PlaybookConcurrencyError } from '../playbook-service.js';
import type { PrismaClient } from '@prisma/client';

// ── Mock transaction-scoped client ──────────────────────────────────────────

const mockTxPrisma = {
  playbookRun: {
    count: vi.fn(),
    create: vi.fn(),
  },
};

// ── Mock top-level Prisma client ────────────────────────────────────────────

const mockPrisma = {
  playbook: {
    findUnique: vi.fn(),
    findMany: vi.fn(),
    create: vi.fn(),
  },
  playbookRun: {
    count: vi.fn(),
    create: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
  },
  warRoom: {
    findUnique: vi.fn(),
  },
  $transaction: vi.fn().mockImplementation(async (cb: unknown) => {
    if (typeof cb === 'function') return (cb as (tx: typeof mockTxPrisma) => unknown)(mockTxPrisma);
    return Promise.all(cb as Promise<unknown>[]);
  }),
} as unknown as PrismaClient;

// ── Mock logger ─────────────────────────────────────────────────────────────

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
};

// ── Shared fixtures ─────────────────────────────────────────────────────────

const TENANT_ID = 'tenant-1';
const OTHER_TENANT_ID = 'tenant-OTHER';

const user = { userId: 'user-1', userName: 'Test User' };

const playbookFixture = {
  id: 'playbook-1',
  tenantId: TENANT_ID,
  name: 'Emergency Playbook',
  steps: [],
};

const warRoomFixture = {
  id: 'warroom-1',
  tenantId: TENANT_ID,
};

const createdRunFixture = {
  id: 'run-1',
  playbookId: 'playbook-1',
  warRoomId: 'warroom-1',
  tenantId: TENANT_ID,
  status: 'RUNNING',
  currentStep: 0,
  stepResults: [],
  startedBy: 'user-1',
};

// ── Test suite ──────────────────────────────────────────────────────────────

describe('PlaybookService.runPlaybook', () => {
  let service: PlaybookService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new PlaybookService(mockPrisma, mockLogger);
  });

  // ── Happy path ──────────────────────────────────────────────────────────

  it('creates a run with status RUNNING when all checks pass', async () => {
    mockPrisma.playbook.findUnique.mockResolvedValue(playbookFixture);
    mockPrisma.warRoom.findUnique.mockResolvedValue(warRoomFixture);
    mockTxPrisma.playbookRun.count.mockResolvedValueOnce(0); // no existing run in war room
    mockTxPrisma.playbookRun.count.mockResolvedValueOnce(0); // tenant active runs
    mockTxPrisma.playbookRun.create.mockResolvedValue(createdRunFixture);

    const result = await service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, user);

    expect(result).toEqual(createdRunFixture);
    expect(result.status).toBe('RUNNING');
    expect(result.startedBy).toBe(user.userId);

    // Verify the transaction was called with Serializable isolation
    expect(mockPrisma.$transaction).toHaveBeenCalledWith(
      expect.any(Function),
      expect.objectContaining({
        isolationLevel: 'Serializable',
      })
    );
  });

  // ── Concurrency: same playbook already running in the same war room ───

  it('throws PlaybookConcurrencyError (409) when same playbook is already running in the war room', async () => {
    mockPrisma.playbook.findUnique.mockResolvedValue(playbookFixture);
    mockPrisma.warRoom.findUnique.mockResolvedValue(warRoomFixture);

    // First count call: existing run found in this war room
    mockTxPrisma.playbookRun.count.mockResolvedValueOnce(1);

    let caught: unknown;
    try {
      await service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, user);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(PlaybookConcurrencyError);
    const error = caught as PlaybookConcurrencyError;
    expect(error.statusCode).toBe(409);
    expect(error.code).toBe('CONCURRENCY_CONFLICT');

    // The run should never have been created
    expect(mockTxPrisma.playbookRun.create).not.toHaveBeenCalled();
  });

  // ── Concurrency: tenant max concurrent runs reached ───────────────────

  it('throws PlaybookConcurrencyError (409) when tenant has reached max concurrent runs', async () => {
    mockPrisma.playbook.findUnique.mockResolvedValue(playbookFixture);
    mockPrisma.warRoom.findUnique.mockResolvedValue(warRoomFixture);

    // First count: no existing run in this specific war room
    mockTxPrisma.playbookRun.count.mockResolvedValueOnce(0);
    // Second count: tenant already has 5 active runs
    mockTxPrisma.playbookRun.count.mockResolvedValueOnce(5);

    let caught: unknown;
    try {
      await service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, user);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(PlaybookConcurrencyError);
    const error = caught as PlaybookConcurrencyError;
    expect(error.statusCode).toBe(409);
    expect(error.code).toBe('CONCURRENCY_CONFLICT');

    expect(mockTxPrisma.playbookRun.create).not.toHaveBeenCalled();
  });

  // ── Tenant isolation: playbook belongs to different tenant ────────────

  it('throws "Playbook not found" when playbook belongs to a different tenant', async () => {
    mockPrisma.playbook.findUnique.mockResolvedValue({
      ...playbookFixture,
      tenantId: OTHER_TENANT_ID,
    });

    await expect(
      service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, user)
    ).rejects.toThrow('Playbook not found');

    // Must not proceed to war room lookup or transaction
    expect(mockPrisma.warRoom.findUnique).not.toHaveBeenCalled();
    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  // ── Tenant isolation: war room belongs to different tenant ────────────

  it('throws "War room not found" when war room belongs to a different tenant', async () => {
    mockPrisma.playbook.findUnique.mockResolvedValue(playbookFixture);
    mockPrisma.warRoom.findUnique.mockResolvedValue({
      ...warRoomFixture,
      tenantId: OTHER_TENANT_ID,
    });

    await expect(
      service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, user)
    ).rejects.toThrow('War room not found');

    // Must not proceed to the transaction
    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  // ── Input validation: missing userId ──────────────────────────────────

  it('throws "User ID is required" when user.userId is missing', async () => {
    const noIdUser = { userId: '', userName: 'Ghost' };

    await expect(
      service.runPlaybook('playbook-1', 'warroom-1', TENANT_ID, noIdUser)
    ).rejects.toThrow('User ID is required');

    // Must not touch the database at all
    expect(mockPrisma.playbook.findUnique).not.toHaveBeenCalled();
    expect(mockPrisma.warRoom.findUnique).not.toHaveBeenCalled();
    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });
});
