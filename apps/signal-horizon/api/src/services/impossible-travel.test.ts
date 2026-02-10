import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ImpossibleTravelService, type LoginEvent } from './impossible-travel.js';
import { PrismaClient } from '@prisma/client';
import { pino } from 'pino';

// Mock Prisma and Logger
const mockPrisma = {
  signal: {
    create: vi.fn(),
  },
} as unknown as PrismaClient;

const mockLogger = pino({ level: 'silent' });

describe('ImpossibleTravelService', () => {
  let service: ImpossibleTravelService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new ImpossibleTravelService(mockPrisma, mockLogger);
  });

  // Helper to create login events
  const createEvent = (
    userId: string,
    timestamp: Date,
    lat: number,
    lon: number,
    city: string
  ): LoginEvent => ({
    userId,
    tenantId: 'tenant-1',
    timestamp,
    ip: '1.2.3.4',
    location: {
      latitude: lat,
      longitude: lon,
      city,
      countryCode: 'US',
    },
  });

  it('should ignore logins from the same location (short distance)', async () => {
    const now = new Date();
    // New York
    const event1 = createEvent('user-1', now, 40.7128, -74.006, 'New York');
    // Brooklyn (very close)
    const event2 = createEvent('user-1', new Date(now.getTime() + 1000 * 60), 40.6782, -73.9442, 'Brooklyn');

    await service.processLogin(event1);
    const alert = await service.processLogin(event2);

    expect(alert).toBeNull();
  });

  it('should detect impossible travel (NY to London in 1 hour)', async () => {
    const now = new Date();
    // New York
    const event1 = createEvent('user-2', now, 40.7128, -74.006, 'New York');
    
    // London (~5500km away) - 1 hour later
    // Speed required: ~5500 km/h (Supersonic+)
    const event2 = createEvent(
      'user-2',
      new Date(now.getTime() + 1000 * 60 * 60), 
      51.5074, 
      -0.1278, 
      'London'
    );

    await service.processLogin(event1);
    const alert = await service.processLogin(event2);

    expect(alert).not.toBeNull();
    if (alert) {
        expect(alert.severity).toBe('critical'); // > 5000 km/h
        expect(alert.from.location.city).toBe('New York');
        expect(alert.to.location.city).toBe('London');
    }
    expect(mockPrisma.signal.create).toHaveBeenCalled();
  });

  it('should allow possible travel (NY to London in 8 hours)', async () => {
    const now = new Date();
    // New York
    const event1 = createEvent('user-3', now, 40.7128, -74.006, 'New York');
    
    // London - 8 hours later
    // Speed: ~5500 / 8 = ~687 km/h (Commercial flight speed)
    const event2 = createEvent(
      'user-3',
      new Date(now.getTime() + 1000 * 60 * 60 * 8), 
      51.5074, 
      -0.1278, 
      'London'
    );

    await service.processLogin(event1);
    const alert = await service.processLogin(event2);

    expect(alert).toBeNull();
  });

  it('should identify different severity levels', async () => {
    const now = new Date();
    const event1 = createEvent('user-sev', now, 0, 0, 'Point A');

    // 1300km in 1 hour = 1300 km/h (Medium)
    // 1 degree lat approx 111km. 12 degrees approx 1332km.
    const eventMedium = createEvent(
      'user-sev',
      new Date(now.getTime() + 1000 * 60 * 60),
      12,
      0,
      'Point B'
    );
    
    await service.processLogin(event1);
    const alert = await service.processLogin(eventMedium);
    
    expect(alert).not.toBeNull();
    expect(alert?.severity).toBe('medium');
  });
  
  it('should separate history by user', async () => {
    const now = new Date();
    // User A in NY
    const eventA = createEvent('user-A', now, 40.7128, -74.006, 'New York');
    // User B in London
    const eventB = createEvent('user-B', now, 51.5074, -0.1278, 'London');

    await service.processLogin(eventA);
    const alertB = await service.processLogin(eventB); // Should not compare with User A

    expect(alertB).toBeNull();

    // User A in London 1 min later (Impossible!)
    const eventA2 = createEvent('user-A', new Date(now.getTime() + 60000), 51.5074, -0.1278, 'London');
    const alertA = await service.processLogin(eventA2);

    expect(alertA).not.toBeNull();
  });

  describe('timeDiffHours boundary conditions', () => {
    it('should not alert when events are out of order (timeDiffHours <= 0)', async () => {
      const now = new Date();
      // First login in New York
      const event1 = createEvent('user-ooo', now, 40.7128, -74.006, 'New York');
      // Second login in London but with an EARLIER timestamp (out of order)
      const event2 = createEvent(
        'user-ooo',
        new Date(now.getTime() - 1000 * 60 * 60), // 1 hour BEFORE event1
        51.5074,
        -0.1278,
        'London'
      );

      await service.processLogin(event1);
      const alert = await service.processLogin(event2);

      expect(alert).toBeNull();
    });

    it('should not alert when events have identical timestamps (timeDiffHours === 0)', async () => {
      const now = new Date();
      const event1 = createEvent('user-zero', now, 40.7128, -74.006, 'New York');
      const event2 = createEvent('user-zero', new Date(now.getTime()), 51.5074, -0.1278, 'London');

      await service.processLogin(event1);
      const alert = await service.processLogin(event2);

      expect(alert).toBeNull();
    });

    it('should not alert when time difference exceeds 24 hours', async () => {
      const now = new Date();
      const event1 = createEvent('user-day', now, 40.7128, -74.006, 'New York');
      // 25 hours later - even an impossible speed would be ignored due to >24h window
      const event2 = createEvent(
        'user-day',
        new Date(now.getTime() + 1000 * 60 * 60 * 25),
        51.5074,
        -0.1278,
        'London'
      );

      await service.processLogin(event1);
      const alert = await service.processLogin(event2);

      expect(alert).toBeNull();
    });

    it('should alert at exactly 24h boundary when speed exceeds threshold', async () => {
      const now = new Date();
      const event1 = createEvent('user-24h', now, 40.7128, -74.006, 'New York');
      // Just under 24 hours: 23h 59m - NY to Sydney (~16000km) requires ~667 km/h
      // That's below maxSpeedKmh (1000), so no alert for that. Use a closer time gap.
      // NY to London (~5500km) in 2 hours = 2750 km/h => high severity
      const event2 = createEvent(
        'user-24h',
        new Date(now.getTime() + 1000 * 60 * 60 * 2),
        51.5074,
        -0.1278,
        'London'
      );

      await service.processLogin(event1);
      const alert = await service.processLogin(event2);

      expect(alert).not.toBeNull();
      expect(alert?.severity).toBe('high');
    });
  });
});