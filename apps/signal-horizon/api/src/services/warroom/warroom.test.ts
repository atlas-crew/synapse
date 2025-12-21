/**
 * War Room Service Tests
 * Tests war room lifecycle, activities, campaign linking, and quick actions
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WarRoomService, type WarRoomConfig } from './index.js';
import type { PrismaClient, WarRoom, WarRoomActivity, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { DashboardGateway } from '../../websocket/dashboard-gateway.js';

// Mock Prisma client with transaction support
const mockTx = {
  warRoom: {
    create: vi.fn(),
    findUnique: vi.fn(),
  },
  warRoomActivity: {
    create: vi.fn(),
  },
  warRoomCampaign: {
    createMany: vi.fn(),
  },
};

const mockPrisma = {
  $transaction: vi.fn((callback) => callback(mockTx)),
  warRoom: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    count: vi.fn(),
  },
  warRoomActivity: {
    create: vi.fn(),
    findMany: vi.fn(),
    count: vi.fn(),
  },
  warRoomCampaign: {
    createMany: vi.fn(),
    findMany: vi.fn(),
    findFirst: vi.fn(),
  },
  blocklistEntry: {
    create: vi.fn(),
    deleteMany: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

// Mock Dashboard Gateway
const mockDashboardGateway = {
  broadcastToTenant: vi.fn(),
  broadcastAll: vi.fn(),
} as unknown as DashboardGateway;

const defaultConfig: WarRoomConfig = {
  autoCreateForCrossTenant: true,
  autoCreateForCritical: true,
  maxActivityLimit: 100,
};

function createWarRoom(overrides: Partial<WarRoom> = {}): WarRoom {
  return {
    id: 'warroom-123',
    tenantId: 'tenant-1',
    name: 'Incident Response',
    description: 'Responding to attack campaign',
    status: 'ACTIVE',
    priority: 'HIGH',
    leaderId: 'user-1',
    closedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as WarRoom;
}

function createActivity(overrides: Partial<WarRoomActivity> = {}): WarRoomActivity {
  return {
    id: 'activity-123',
    warRoomId: 'warroom-123',
    tenantId: 'tenant-1',
    actorType: 'USER',
    actorId: 'user-1',
    actorName: 'John Doe',
    actionType: 'MESSAGE',
    description: 'Test message',
    metadata: {},
    createdAt: new Date(),
    ...overrides,
  } as WarRoomActivity;
}

describe('WarRoomService', () => {
  let warRoomService: WarRoomService;

  beforeEach(() => {
    vi.clearAllMocks();
    warRoomService = new WarRoomService(mockPrisma, mockLogger, defaultConfig);
    warRoomService.setDashboardGateway(mockDashboardGateway);

    // Setup default transaction mock
    mockTx.warRoom.create.mockResolvedValue(createWarRoom());
    mockTx.warRoomActivity.create.mockResolvedValue(createActivity());
    mockTx.warRoomCampaign.createMany.mockResolvedValue({ count: 1 });
  });

  describe('createWarRoom', () => {
    it('should create a war room with default priority', async () => {
      const result = await warRoomService.createWarRoom({
        tenantId: 'tenant-1',
        name: 'New Incident',
      });

      expect(result.id).toBe('warroom-123');
      expect(mockTx.warRoom.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tenantId: 'tenant-1',
          name: 'New Incident',
          priority: 'MEDIUM',
          status: 'ACTIVE',
        }),
      });
    });

    it('should create war room with specified priority', async () => {
      await warRoomService.createWarRoom({
        tenantId: 'tenant-1',
        name: 'Critical Incident',
        priority: 'CRITICAL',
      });

      expect(mockTx.warRoom.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          priority: 'CRITICAL',
        }),
      });
    });

    it('should log creation activity', async () => {
      await warRoomService.createWarRoom({
        tenantId: 'tenant-1',
        name: 'New Incident',
      });

      expect(mockTx.warRoomActivity.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          actorType: 'SYSTEM',
          actionType: 'STATUS_CHANGED',
          description: expect.stringContaining('created'),
        }),
      });
    });

    it('should link campaigns when provided', async () => {
      await warRoomService.createWarRoom({
        tenantId: 'tenant-1',
        name: 'Campaign Response',
        campaignIds: ['campaign-1', 'campaign-2'],
      });

      expect(mockTx.warRoomCampaign.createMany).toHaveBeenCalledWith({
        data: [
          { warRoomId: 'warroom-123', campaignId: 'campaign-1', linkedBy: 'SYSTEM' },
          { warRoomId: 'warroom-123', campaignId: 'campaign-2', linkedBy: 'SYSTEM' },
        ],
        skipDuplicates: true,
      });
    });
  });

  describe('getWarRoom', () => {
    it('should return war room with activities', async () => {
      const warRoomWithActivities = {
        ...createWarRoom(),
        activities: [createActivity()],
        _count: { activities: 1, campaignLinks: 0 },
      };

      vi.mocked(mockPrisma.warRoom.findUnique).mockResolvedValue(warRoomWithActivities as never);

      const result = await warRoomService.getWarRoom('warroom-123');

      expect(result?.id).toBe('warroom-123');
      expect(result?.activities).toHaveLength(1);
    });

    it('should return null for non-existent war room', async () => {
      vi.mocked(mockPrisma.warRoom.findUnique).mockResolvedValue(null);

      const result = await warRoomService.getWarRoom('non-existent');

      expect(result).toBeNull();
    });

    it('should limit activities to config max', async () => {
      await warRoomService.getWarRoom('warroom-123', 200);

      expect(mockPrisma.warRoom.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          include: expect.objectContaining({
            activities: expect.objectContaining({
              take: defaultConfig.maxActivityLimit,
            }),
          }),
        })
      );
    });
  });

  describe('listActiveWarRooms', () => {
    it('should return active and paused war rooms', async () => {
      vi.mocked(mockPrisma.warRoom.findMany).mockResolvedValue([
        createWarRoom({ status: 'ACTIVE' }),
        createWarRoom({ id: 'warroom-456', status: 'PAUSED' }),
      ]);

      const result = await warRoomService.listActiveWarRooms('tenant-1');

      expect(result).toHaveLength(2);
      expect(mockPrisma.warRoom.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            tenantId: 'tenant-1',
            status: { in: ['ACTIVE', 'PAUSED'] },
          },
        })
      );
    });
  });

  describe('updateStatus', () => {
    it('should update status and log activity', async () => {
      vi.mocked(mockPrisma.warRoom.update).mockResolvedValue(createWarRoom({ status: 'CLOSED' }));
      vi.mocked(mockPrisma.warRoomActivity.create).mockResolvedValue(createActivity());

      const result = await warRoomService.updateStatus(
        'warroom-123',
        'CLOSED',
        'user-1',
        'John Doe'
      );

      expect(result.status).toBe('CLOSED');
      expect(mockPrisma.warRoom.update).toHaveBeenCalledWith({
        where: { id: 'warroom-123' },
        data: expect.objectContaining({
          status: 'CLOSED',
          closedAt: expect.any(Date),
        }),
      });
    });

    it('should broadcast status change to dashboards', async () => {
      vi.mocked(mockPrisma.warRoom.update).mockResolvedValue(createWarRoom({ status: 'CLOSED' }));
      vi.mocked(mockPrisma.warRoomActivity.create).mockResolvedValue(createActivity());

      await warRoomService.updateStatus('warroom-123', 'CLOSED', 'user-1', 'John Doe');

      expect(mockDashboardGateway.broadcastAll).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'war-room-status',
          warRoomId: 'warroom-123',
          status: 'CLOSED',
        })
      );
    });
  });

  describe('addMessage', () => {
    it('should add user message to war room', async () => {
      vi.mocked(mockPrisma.warRoomActivity.create).mockResolvedValue(
        createActivity({ description: 'Test message' })
      );

      const result = await warRoomService.addMessage(
        'warroom-123',
        'tenant-1',
        'user-1',
        'John Doe',
        'Test message'
      );

      expect(result.description).toBe('Test message');
      expect(mockPrisma.warRoomActivity.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          actionType: 'MESSAGE',
          actorType: 'USER',
          actorName: 'John Doe',
          description: 'Test message',
        }),
      });
    });

    it('should broadcast activity to dashboards', async () => {
      vi.mocked(mockPrisma.warRoomActivity.create).mockResolvedValue(createActivity());

      await warRoomService.addMessage('warroom-123', 'tenant-1', 'user-1', 'John Doe', 'Message');

      expect(mockDashboardGateway.broadcastToTenant).toHaveBeenCalledWith(
        'tenant-1',
        expect.objectContaining({
          type: 'war-room-activity',
          warRoomId: 'warroom-123',
        })
      );
    });
  });

  describe('getActivities', () => {
    it('should return activities with pagination', async () => {
      vi.mocked(mockPrisma.warRoomActivity.findMany).mockResolvedValue([
        createActivity({ id: 'activity-1' }),
        createActivity({ id: 'activity-2' }),
      ]);

      const result = await warRoomService.getActivities('warroom-123', 50);

      expect(result.activities).toHaveLength(2);
      expect(result.nextCursor).toBeUndefined();
    });

    it('should return next cursor when more activities exist', async () => {
      const activities = Array.from({ length: 51 }, (_, i) =>
        createActivity({ id: `activity-${i}` })
      );
      vi.mocked(mockPrisma.warRoomActivity.findMany).mockResolvedValue(activities);

      const result = await warRoomService.getActivities('warroom-123', 50);

      expect(result.activities).toHaveLength(50);
      expect(result.nextCursor).toBe('activity-49');
    });
  });

  describe('createBlock', () => {
    it('should create block and log activity', async () => {
      const mockBlockTx = {
        blocklistEntry: {
          create: vi.fn().mockResolvedValue({}),
        },
        warRoomActivity: {
          create: vi.fn().mockResolvedValue(createActivity()),
        },
      };
      vi.mocked(mockPrisma.$transaction).mockImplementation((callback) =>
        callback(mockBlockTx as never)
      );

      await warRoomService.createBlock(
        'warroom-123',
        'tenant-1',
        { type: 'add', blockType: 'IP', indicator: '10.0.0.1', reason: 'Malicious' },
        'user-1',
        'John Doe'
      );

      expect(mockBlockTx.blocklistEntry.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          blockType: 'IP',
          indicator: '10.0.0.1',
          source: 'WAR_ROOM',
        }),
      });

      expect(mockBlockTx.warRoomActivity.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          actionType: 'BLOCK_CREATED',
          description: 'Blocked IP: 10.0.0.1',
        }),
      });
    });
  });

  describe('onCampaignDetected', () => {
    beforeEach(() => {
      // Reset transaction mock for onCampaignDetected tests
      vi.mocked(mockPrisma.$transaction).mockImplementation((callback) => callback(mockTx as never));
    });

    it('should auto-create war room for cross-tenant campaign', async () => {
      vi.mocked(mockPrisma.warRoomCampaign.findFirst).mockResolvedValue(null);

      const campaign = {
        id: 'campaign-1',
        name: 'Cross-tenant Attack',
        severity: 'HIGH',
        isCrossTenant: true,
        tenantsAffected: 3,
        tenantId: 'tenant-1',
        description: 'Attack description',
      } as Campaign & { severity: string };

      await warRoomService.onCampaignDetected(campaign);

      expect(mockPrisma.$transaction).toHaveBeenCalled();
    });

    it('should auto-create war room for CRITICAL campaign', async () => {
      vi.mocked(mockPrisma.warRoomCampaign.findFirst).mockResolvedValue(null);

      const campaign = {
        id: 'campaign-1',
        name: 'Critical Attack',
        severity: 'CRITICAL',
        isCrossTenant: false,
        tenantsAffected: 1,
        tenantId: 'tenant-1',
        description: null,
      } as Campaign & { severity: string };

      await warRoomService.onCampaignDetected(campaign);

      expect(mockPrisma.$transaction).toHaveBeenCalled();
    });

    it('should not create duplicate war room for same campaign', async () => {
      vi.mocked(mockPrisma.warRoomCampaign.findFirst).mockResolvedValue({
        warRoom: createWarRoom(),
      } as never);

      const campaign = {
        id: 'campaign-1',
        name: 'Existing Campaign',
        severity: 'CRITICAL',
        isCrossTenant: true,
        tenantsAffected: 3,
        tenantId: 'tenant-1',
        description: null,
      } as Campaign & { severity: string };

      await warRoomService.onCampaignDetected(campaign);

      // Transaction should not be called since campaign already linked
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });
  });

  describe('getStats', () => {
    it('should return war room statistics', async () => {
      vi.mocked(mockPrisma.warRoom.count).mockResolvedValue(3);
      vi.mocked(mockPrisma.warRoomActivity.count)
        .mockResolvedValueOnce(150) // activities last 24h
        .mockResolvedValueOnce(25); // blocks created last 24h

      const result = await warRoomService.getStats('tenant-1');

      expect(result.activeWarRooms).toBe(3);
      expect(result.activitiesLast24h).toBe(150);
      expect(result.blocksCreatedLast24h).toBe(25);
    });
  });
});
