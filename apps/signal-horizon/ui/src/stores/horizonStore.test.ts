/**
 * Horizon Store Tests
 * Tests Zustand store for real-time threat intelligence state
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { useHorizonStore } from './horizonStore';
import type { Campaign, Threat, ThreatAlert } from './horizonStore';

// Helper to reset store between tests
function resetStore() {
  useHorizonStore.setState({
    campaigns: [],
    threats: [],
    alerts: [],
    sensorStats: {},
    stats: {
      totalThreats: 0,
      fleetThreats: 0,
      activeCampaigns: 0,
      blockedIndicators: 0,
      sensorsOnline: 0,
      apiStats: {
        discoveryEvents: 0,
        schemaViolations: 0,
      },
    },
    connectionState: 'disconnected',
    sessionId: null,
    isLoading: true,
    hasReceivedSnapshot: false,
  });
}

const mockCampaign: Campaign = {
  id: 'campaign-1',
  name: 'Test Campaign',
  status: 'ACTIVE',
  severity: 'HIGH',
  isCrossTenant: true,
  tenantsAffected: 3,
  confidence: 0.92,
  firstSeenAt: new Date().toISOString(),
  lastActivityAt: new Date().toISOString(),
};

const mockThreat: Threat = {
  id: 'threat-1',
  threatType: 'CREDENTIAL_STUFFING',
  indicator: '192.168.1.100',
  riskScore: 85,
  hitCount: 150,
  tenantsAffected: 2,
  isFleetThreat: true,
  firstSeenAt: new Date().toISOString(),
  lastSeenAt: new Date().toISOString(),
};

const mockAlert: ThreatAlert = {
  id: 'alert-1',
  type: 'campaign',
  title: 'High-Risk Campaign Detected',
  description: 'Cross-tenant attack campaign targeting 3 customers',
  severity: 'CRITICAL',
  timestamp: Date.now(),
};

describe('horizonStore', () => {
  beforeEach(() => {
    resetStore();
  });

  describe('initial state', () => {
    it('should start with empty collections and loading state', () => {
      const state = useHorizonStore.getState();

      expect(state.campaigns).toEqual([]);
      expect(state.threats).toEqual([]);
      expect(state.alerts).toEqual([]);
      expect(state.isLoading).toBe(true);
      expect(state.hasReceivedSnapshot).toBe(false);
      expect(state.connectionState).toBe('disconnected');
    });
  });

  describe('setConnectionState', () => {
    it('should update connection state', () => {
      const { setConnectionState } = useHorizonStore.getState();

      setConnectionState('connecting');
      expect(useHorizonStore.getState().connectionState).toBe('connecting');

      setConnectionState('connected');
      expect(useHorizonStore.getState().connectionState).toBe('connected');
    });
  });

  describe('setLoading', () => {
    it('should update loading state', () => {
      const { setLoading } = useHorizonStore.getState();

      setLoading(false);
      expect(useHorizonStore.getState().isLoading).toBe(false);

      setLoading(true);
      expect(useHorizonStore.getState().isLoading).toBe(true);
    });
  });

  describe('setSnapshot', () => {
    it('should set initial snapshot and mark loading complete', () => {
      const { setSnapshot } = useHorizonStore.getState();

      setSnapshot({
        activeCampaigns: [mockCampaign],
        recentThreats: [mockThreat],
        sensorStats: { CONNECTED: 5 },
        apiStats: {
          discoveryEvents: 0,
          schemaViolations: 0,
        },
      });

      const state = useHorizonStore.getState();
      expect(state.campaigns).toHaveLength(1);
      expect(state.threats).toHaveLength(1);
      expect(state.stats.activeCampaigns).toBe(1);
      expect(state.stats.totalThreats).toBe(1);
      expect(state.stats.sensorsOnline).toBe(5);
      expect(state.isLoading).toBe(false);
      expect(state.hasReceivedSnapshot).toBe(true);
    });
  });

  describe('addCampaign', () => {
    it('should add campaign to the beginning of the list', () => {
      const { addCampaign } = useHorizonStore.getState();

      addCampaign(mockCampaign);
      expect(useHorizonStore.getState().campaigns).toHaveLength(1);

      const secondCampaign = { ...mockCampaign, id: 'campaign-2', name: 'Second Campaign' };
      addCampaign(secondCampaign);

      const campaigns = useHorizonStore.getState().campaigns;
      expect(campaigns).toHaveLength(2);
      expect(campaigns[0].id).toBe('campaign-2'); // Newest first
    });

    it('should update existing campaign instead of duplicating', () => {
      const { addCampaign } = useHorizonStore.getState();

      addCampaign(mockCampaign);
      addCampaign({ ...mockCampaign, tenantsAffected: 5 });

      const campaigns = useHorizonStore.getState().campaigns;
      expect(campaigns).toHaveLength(1);
      expect(campaigns[0].tenantsAffected).toBe(5);
    });
  });

  describe('addThreat', () => {
    it('should add threat to the beginning of the list', () => {
      const { addThreat } = useHorizonStore.getState();

      addThreat(mockThreat);
      expect(useHorizonStore.getState().threats).toHaveLength(1);

      const secondThreat = { ...mockThreat, id: 'threat-2', indicator: '10.0.0.1' };
      addThreat(secondThreat);

      const threats = useHorizonStore.getState().threats;
      expect(threats).toHaveLength(2);
      expect(threats[0].id).toBe('threat-2'); // Newest first
    });

    it('should limit threats to 100 items', () => {
      const { addThreat } = useHorizonStore.getState();

      // Add 105 threats
      for (let i = 0; i < 105; i++) {
        addThreat({ ...mockThreat, id: `threat-${i}` });
      }

      expect(useHorizonStore.getState().threats).toHaveLength(100);
    });
  });

  describe('addAlert', () => {
    it('should add alert to the beginning of the list', () => {
      const { addAlert } = useHorizonStore.getState();

      addAlert(mockAlert);
      expect(useHorizonStore.getState().alerts).toHaveLength(1);

      const secondAlert = { ...mockAlert, id: 'alert-2', title: 'Second Alert' };
      addAlert(secondAlert);

      const alerts = useHorizonStore.getState().alerts;
      expect(alerts).toHaveLength(2);
      expect(alerts[0].id).toBe('alert-2'); // Newest first
    });

    it('should limit alerts to 50 items', () => {
      const { addAlert } = useHorizonStore.getState();

      // Add 55 alerts
      for (let i = 0; i < 55; i++) {
        addAlert({ ...mockAlert, id: `alert-${i}` });
      }

      expect(useHorizonStore.getState().alerts).toHaveLength(50);
    });
  });

  describe('updateStats', () => {
    it('should merge new stats with existing', () => {
      const { updateStats } = useHorizonStore.getState();

      updateStats({ fleetThreats: 10 });
      expect(useHorizonStore.getState().stats.fleetThreats).toBe(10);

      updateStats({ activeCampaigns: 5 });
      const stats = useHorizonStore.getState().stats;
      expect(stats.fleetThreats).toBe(10);
      expect(stats.activeCampaigns).toBe(5);
    });
  });

  describe('updateCampaign', () => {
    it('should update campaign by id', () => {
      const { addCampaign, updateCampaign } = useHorizonStore.getState();

      addCampaign(mockCampaign);
      updateCampaign('campaign-1', { status: 'RESOLVED' });

      const campaigns = useHorizonStore.getState().campaigns;
      expect(campaigns[0].status).toBe('RESOLVED');
    });
  });

  describe('clearAlerts', () => {
    it('should clear all alerts', () => {
      const { addAlert, clearAlerts } = useHorizonStore.getState();

      addAlert(mockAlert);
      addAlert({ ...mockAlert, id: 'alert-2' });

      clearAlerts();

      expect(useHorizonStore.getState().alerts).toHaveLength(0);
    });
  });
});
