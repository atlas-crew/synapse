import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatService, type SignalContext } from './threat-service.js';
import pino from 'pino';

describe('ThreatService', () => {
  let service: ThreatService;
  const logger = pino({ level: 'silent' });

  beforeEach(() => {
    service = new ThreatService(logger);
  });

  afterEach(async () => {
    await service.stop();
  });

  describe('calculateThreatScore', () => {
    it('should score CREDENTIAL_STUFFING signals high', async () => {
      const signal: SignalContext = {
        signalType: 'CREDENTIAL_STUFFING',
        severity: 'HIGH',
        confidence: 0.9,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.score).toBeGreaterThanOrEqual(60);
      expect(result.recommendedAction).toBe('alert');
    });

    it('should score IMPOSSIBLE_TRAVEL as critical threat', async () => {
      const signal: SignalContext = {
        signalType: 'IMPOSSIBLE_TRAVEL',
        severity: 'CRITICAL',
        confidence: 0.95,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.recommendedAction).toBe('alert');
    });

    it('should score TEMPLATE_DISCOVERY signals lower', async () => {
      const signal: SignalContext = {
        signalType: 'TEMPLATE_DISCOVERY',
        severity: 'LOW',
        confidence: 0.5,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.score).toBeLessThan(40);
      // Low scores get 'allow' action (below monitor threshold of 30)
      expect(result.recommendedAction).toBe('allow');
    });

    it('should increase score for repeat offenders', async () => {
      const signal: SignalContext = {
        signalType: 'BOT_SIGNATURE',
        severity: 'MEDIUM',
        confidence: 0.7,
        sourceIp: '192.168.1.100',
        eventCount: 1,
      };

      // First signal
      const first = await service.calculateThreatScore(signal);

      // Same IP, many events
      const repeat = await service.calculateThreatScore({
        ...signal,
        eventCount: 100,
      });

      expect(repeat.score).toBeGreaterThan(first.score);
    });

    it('should include factor breakdown', async () => {
      const signal: SignalContext = {
        signalType: 'IP_THREAT',
        severity: 'HIGH',
        confidence: 0.8,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.factors).toHaveLength(4);
      expect(result.factors.map((f) => f.name)).toEqual(
        expect.arrayContaining(['severity', 'signalType', 'confidence', 'volume'])
      );
    });

    it('should cap score at 100', async () => {
      const signal: SignalContext = {
        signalType: 'IMPOSSIBLE_TRAVEL',
        severity: 'CRITICAL',
        confidence: 1.0,
        eventCount: 1000,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.score).toBeLessThanOrEqual(100);
    });
  });

  describe('severityRank', () => {
    it('should rank severities correctly', () => {
      expect(service.severityRank('LOW')).toBe(25);
      expect(service.severityRank('MEDIUM')).toBe(50);
      expect(service.severityRank('HIGH')).toBe(75);
      expect(service.severityRank('CRITICAL')).toBe(100);
    });
  });

  describe('higherSeverity', () => {
    it('should return the higher severity', () => {
      expect(service.higherSeverity('LOW', 'HIGH')).toBe('HIGH');
      expect(service.higherSeverity('CRITICAL', 'MEDIUM')).toBe('CRITICAL');
      expect(service.higherSeverity('MEDIUM', 'MEDIUM')).toBe('MEDIUM');
    });
  });

  describe('getVolumeStats', () => {
    it('should track volume statistics', async () => {
      const signal: SignalContext = {
        signalType: 'RATE_ANOMALY',
        severity: 'MEDIUM',
        confidence: 0.7,
        sourceIp: '10.0.0.1',
      };

      await service.calculateThreatScore(signal);
      await service.calculateThreatScore({ ...signal, sourceIp: '10.0.0.2' });
      await service.calculateThreatScore({ ...signal, sourceIp: '10.0.0.3' });

      const stats = await service.getVolumeStats();

      expect(stats.trackedEntities).toBe(3);
      expect(stats.totalSignals).toBe(3);
    });
  });

  describe('recommended actions', () => {
    it('should recommend allow for low scores', async () => {
      const signal: SignalContext = {
        signalType: 'TEMPLATE_DISCOVERY',
        severity: 'LOW',
        confidence: 0.3,
      };

      const result = await service.calculateThreatScore(signal);

      expect(result.recommendedAction).toBe('allow');
    });

    it('should recommend block for high scores', async () => {
      // Create service with lower block threshold for testing
      const strictService = new ThreatService(logger, {
        thresholds: { monitor: 20, alert: 40, block: 60 },
      });

      const signal: SignalContext = {
        signalType: 'IMPOSSIBLE_TRAVEL',
        severity: 'CRITICAL',
        confidence: 0.95,
      };

      const result = await strictService.calculateThreatScore(signal);

      expect(result.recommendedAction).toBe('block');
      await strictService.stop();
    });
  });
});
