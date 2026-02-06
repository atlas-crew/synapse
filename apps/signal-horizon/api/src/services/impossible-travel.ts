/**
 * Impossible Travel Detection Service
 * Identifies geographically impossible travel between login events.
 */

import type { Logger } from 'pino';
import type { PrismaClient, Severity } from '@prisma/client';

export interface GeoLocation {
  latitude: f64;
  longitude: f64;
  city?: string;
  countryCode: string;
}

export interface LoginEvent {
  userId: string;
  tenantId: string;
  timestamp: Date;
  ip: string;
  location: GeoLocation;
  fingerprint?: string;
}

export interface ImpossibleTravelAlert {
  userId: string;
  tenantId: string;
  from: LoginEvent;
  to: LoginEvent;
  distanceKm: number;
  timeDiffHours: number;
  requiredSpeedKmh: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

type f64 = number;

export class ImpossibleTravelService {
  private prisma: PrismaClient;
  private logger: Logger;
  private userHistory: Map<string, LoginEvent[]> = new Map();
  private historyWindowMs = 24 * 60 * 60 * 1000; // 24 hours
  private maxHistoryPerUser = 10;
  private maxSpeedKmh = 1000; // Commercial flight speed approx

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'impossible-travel' });
  }

  /**
   * Process a new login event and check for impossible travel
   */
  async processLogin(event: LoginEvent): Promise<ImpossibleTravelAlert | null> {
    const key = `${event.tenantId}:${event.userId}`;
    let history = this.userHistory.get(key) || [];

    // Clean old history
    const cutoff = Date.now() - this.historyWindowMs;
    history = history.filter((e) => e.timestamp.getTime() > cutoff);

    let alert: ImpossibleTravelAlert | null = null;

    // Check against recent logins
    for (const prev of history) {
      const travelAlert = this.checkTravel(prev, event);
      if (travelAlert) {
        // If we found multiple, keep the one with highest speed/severity
        if (!alert || travelAlert.requiredSpeedKmh > alert.requiredSpeedKmh) {
          alert = travelAlert;
        }
      }
    }

    // Update history
    history.push(event);
    if (history.length > this.maxHistoryPerUser) {
      history.shift();
    }
    this.userHistory.set(key, history);

    if (alert) {
      this.logger.warn(
        {
          userId: alert.userId,
          speed: alert.requiredSpeedKmh,
          distance: alert.distanceKm,
          severity: alert.severity,
        },
        'Impossible travel detected'
      );
      
      // Persist the alert as a signal or threat (optional, based on project needs)
      await this.persistAlert(alert);
    }

    return alert;
  }

  private checkTravel(from: LoginEvent, to: LoginEvent): ImpossibleTravelAlert | null {
    const distance = this.haversineDistance(
      from.location.latitude,
      from.location.longitude,
      to.location.latitude,
      to.location.longitude
    );

    // Ignore if same area (< 50km)
    if (distance < 50) return null;

    const timeDiffMs = to.timestamp.getTime() - from.timestamp.getTime();
    const timeDiffHours = timeDiffMs / (1000 * 60 * 60);

    // Ignore if too much time passed or events are out of order
    if (timeDiffHours <= 0 || timeDiffHours > 24) return null;

    const requiredSpeed = distance / timeDiffHours;

    if (requiredSpeed > this.maxSpeedKmh) {
      return {
        userId: to.userId,
        tenantId: to.tenantId,
        from,
        to,
        distanceKm: Math.round(distance),
        timeDiffHours: Math.round(timeDiffHours * 100) / 100,
        requiredSpeedKmh: Math.round(requiredSpeed),
        severity: this.calculateSeverity(requiredSpeed),
      };
    }

    return null;
  }

  private calculateSeverity(speed: number): ImpossibleTravelAlert['severity'] {
    if (speed > 5000) return 'critical';
    if (speed > 2000) return 'high';
    if (speed > 1200) return 'medium';
    return 'low';
  }

  private haversineDistance(lat1: f64, lon1: f64, lat2: f64, lon2: f64): number {
    const R = 6371; // Earth radius in km
    const dLat = this.toRad(lat2 - lat1);
    const dLon = this.toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRad(lat1)) *
        Math.cos(this.toRad(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRad(value: number): number {
    return (value * Math.PI) / 180;
  }

  private async persistAlert(alert: ImpossibleTravelAlert): Promise<void> {
    try {
      // Create a signal for this impossible travel
      await this.prisma.signal.create({
        data: {
          tenantId: alert.tenantId,
          sensorId: alert.to.userId, // Using userId as sensor context for now
          signalType: 'IMPOSSIBLE_TRAVEL',
          severity: alert.severity.toUpperCase() as Severity,
          confidence: 0.9,
          metadata: {
            alertType: 'impossible_travel',
            distanceKm: alert.distanceKm,
            speedKmh: alert.requiredSpeedKmh,
            from: {
              ip: alert.from.ip,
              city: alert.from.location.city,
              country: alert.from.location.countryCode,
              timestamp: alert.from.timestamp,
            },
            to: {
              ip: alert.to.ip,
              city: alert.to.location.city,
              country: alert.to.location.countryCode,
              timestamp: alert.to.timestamp,
            },
          },
        },
      });
    } catch (error) {
      this.logger.error({ error }, 'Failed to persist impossible travel alert');
    }
  }
}
