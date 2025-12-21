/**
 * Signal Horizon Global State Store
 * Manages real-time threat data, campaigns, and connection state
 */

import { create } from 'zustand';

export interface Campaign {
  id: string;
  name: string;
  description?: string;
  status: 'ACTIVE' | 'MONITORING' | 'RESOLVED' | 'FALSE_POSITIVE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  isCrossTenant: boolean;
  tenantsAffected: number;
  confidence: number;
  firstSeenAt: string;
  lastActivityAt: string;
}

export interface Threat {
  id: string;
  threatType: string;
  indicator: string;
  riskScore: number;
  fleetRiskScore?: number;
  hitCount: number;
  tenantsAffected: number;
  isFleetThreat: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ThreatAlert {
  id: string;
  type: 'campaign' | 'threat' | 'blocklist';
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: number;
}

interface HorizonState {
  // Connection
  connectionState: 'disconnected' | 'connecting' | 'connected' | 'error';
  sessionId: string | null;

  // Loading state
  isLoading: boolean;
  hasReceivedSnapshot: boolean;

  // Data
  campaigns: Campaign[];
  threats: Threat[];
  alerts: ThreatAlert[];
  sensorStats: Record<string, number>;

  // Stats
  stats: {
    totalThreats: number;
    fleetThreats: number;
    activeCampaigns: number;
    blockedIndicators: number;
    sensorsOnline: number;
  };

  // Actions
  setConnectionState: (state: HorizonState['connectionState']) => void;
  setSessionId: (id: string | null) => void;
  setLoading: (loading: boolean) => void;
  setSnapshot: (data: {
    activeCampaigns: Campaign[];
    recentThreats: Threat[];
    sensorStats: Record<string, number>;
  }) => void;
  addCampaign: (campaign: Campaign) => void;
  updateCampaign: (id: string, updates: Partial<Campaign>) => void;
  addThreat: (threat: Threat) => void;
  addAlert: (alert: ThreatAlert) => void;
  clearAlerts: () => void;
  updateStats: (stats: Partial<HorizonState['stats']>) => void;
}

export const useHorizonStore = create<HorizonState>((set, get) => ({
  // Initial state
  connectionState: 'disconnected',
  sessionId: null,
  isLoading: true,
  hasReceivedSnapshot: false,
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
  },

  // Actions
  setConnectionState: (state) => set({ connectionState: state }),
  setSessionId: (id) => set({ sessionId: id }),
  setLoading: (loading) => set({ isLoading: loading }),

  setSnapshot: (data) =>
    set({
      campaigns: data.activeCampaigns,
      threats: data.recentThreats,
      sensorStats: data.sensorStats,
      isLoading: false,
      hasReceivedSnapshot: true,
      stats: {
        ...get().stats,
        activeCampaigns: data.activeCampaigns.length,
        totalThreats: data.recentThreats.length,
        fleetThreats: data.recentThreats.filter((t) => t.isFleetThreat).length,
        sensorsOnline: data.sensorStats.CONNECTED || 0,
      },
    }),

  addCampaign: (campaign) =>
    set((state) => ({
      campaigns: [campaign, ...state.campaigns.filter((c) => c.id !== campaign.id)],
      stats: {
        ...state.stats,
        activeCampaigns: state.stats.activeCampaigns + 1,
      },
    })),

  updateCampaign: (id, updates) =>
    set((state) => ({
      campaigns: state.campaigns.map((c) => (c.id === id ? { ...c, ...updates } : c)),
    })),

  addThreat: (threat) =>
    set((state) => ({
      threats: [threat, ...state.threats.filter((t) => t.id !== threat.id)].slice(0, 100),
      stats: {
        ...state.stats,
        totalThreats: state.stats.totalThreats + 1,
        fleetThreats: threat.isFleetThreat
          ? state.stats.fleetThreats + 1
          : state.stats.fleetThreats,
      },
    })),

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 50),
    })),

  clearAlerts: () => set({ alerts: [] }),

  updateStats: (stats) =>
    set((state) => ({
      stats: { ...state.stats, ...stats },
    })),
}));
