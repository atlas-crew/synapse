/**
 * useBeamDashboard Hook
 * Fetches dashboard summary data from Signal Horizon API
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import type { BeamDashboard, TrafficDataPoint, AttackTypeData } from '../types/beam';

const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

// ============================================================================
// API Response Types (from backend)
// ============================================================================

interface DashboardApiResponse {
  status: 'protected' | 'degraded' | 'critical';
  summary: {
    totalEndpoints: number;
    totalRules: number;
    activeRules: number;
    blocks24h: number;
  };
}

// ============================================================================
// Hook Configuration
// ============================================================================

export interface UseBeamDashboardOptions {
  /** Polling interval in milliseconds (default: 30000 = 30s) */
  pollingInterval?: number;
  /** Whether to start fetching immediately (default: true) */
  autoFetch?: boolean;
  /** API base URL (default: /api/v1) */
  apiBaseUrl?: string;
}

export interface UseBeamDashboardResult {
  data: BeamDashboard | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  isConnected: boolean;
  lastUpdated: Date | null;
}

// ============================================================================
// Demo Data Generator
// ============================================================================

function generateDemoData(): BeamDashboard {
  const now = new Date();
  const trafficTimeline: TrafficDataPoint[] = Array.from({ length: 24 }, (_, i) => {
    const baseRequests = 80000 + Math.random() * 40000;
    const blockedRate = 0.02 + Math.random() * 0.03;
    return {
      timestamp: new Date(now.getTime() - (23 - i) * 3600000).toISOString(),
      requests: Math.round(baseRequests),
      blocked: Math.round(baseRequests * blockedRate),
    };
  });

  const attackTypes: AttackTypeData[] = [
    { type: 'SQL Injection', count: 847, percentage: 29.7 },
    { type: 'Bot Traffic', count: 721, percentage: 25.3 },
    { type: 'XSS', count: 534, percentage: 18.8 },
    { type: 'Brute Force', count: 398, percentage: 14.0 },
    { type: 'Scraping', count: 347, percentage: 12.2 },
  ];

  return {
    status: 'protected',
    siteCount: 12,
    endpointCount: 487,
    activeRuleCount: 34,
    lastUpdated: now.toISOString(),
    summary: {
      requests: { value: 2400000, trend: 12.5, period: '24h' },
      blocked: { value: 72000, trend: -8.3, period: '24h' },
      threats: { value: 2847, trend: 15.2, period: '24h' },
      coverage: { value: 94.2, trend: 2.1, period: '7d' },
    },
    trafficTimeline,
    attackTypes,
    recentThreats: [],
    topEndpoints: [
      { endpoint: '/api/v2/users', threatCount: 234 },
      { endpoint: '/api/v2/auth/login', threatCount: 189 },
      { endpoint: '/api/v2/products', threatCount: 156 },
      { endpoint: '/api/v2/cart', threatCount: 98 },
      { endpoint: '/api/v2/orders', threatCount: 76 },
    ],
    alerts: [],
  };
}

// ============================================================================
// Hook Implementation
// ============================================================================

export function useBeamDashboard(options: UseBeamDashboardOptions = {}): UseBeamDashboardResult {
  const {
    pollingInterval = 30000,
    autoFetch = true,
    apiBaseUrl = '/api/v1',
  } = options;

  const [data, setData] = useState<BeamDashboard | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const intervalRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const fetchData = useCallback(async () => {
    // Cancel any in-flight request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsLoading(true);

    try {
      const response = await fetch(`${apiBaseUrl}/beam/dashboard`, {
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${API_KEY}`,
        },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const apiData = await response.json() as DashboardApiResponse;

      // Transform API response to full dashboard data
      const dashboardData: BeamDashboard = {
        status: apiData.status,
        siteCount: 12, // Will be extended when API provides this
        endpointCount: apiData.summary.totalEndpoints,
        activeRuleCount: apiData.summary.activeRules,
        lastUpdated: new Date().toISOString(),
        summary: {
          requests: { value: 2400000, trend: 12.5, period: '24h' },
          blocked: { value: apiData.summary.blocks24h, trend: -8.3, period: '24h' },
          threats: { value: apiData.summary.blocks24h, trend: 15.2, period: '24h' },
          coverage: { value: (apiData.summary.activeRules / Math.max(apiData.summary.totalRules, 1)) * 100, trend: 2.1, period: '7d' },
        },
        trafficTimeline: [], // Extended by analytics endpoint
        attackTypes: [],
        recentThreats: [],
        topEndpoints: [],
        alerts: [],
      };

      setData(dashboardData);
      setIsConnected(true);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        return;
      }

      console.warn('Failed to fetch beam dashboard, using demo data:', err);
      setError(err as Error);
      setIsConnected(false);

      // Fall back to demo data if we don't have any data yet
      if (!data) {
        setData(generateDemoData());
      }
    } finally {
      setIsLoading(false);
    }
  }, [apiBaseUrl, data]);

  // Initial fetch
  useEffect(() => {
    if (autoFetch) {
      fetchData();
    }

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [autoFetch, fetchData]);

  // Polling
  useEffect(() => {
    if (pollingInterval > 0) {
      intervalRef.current = window.setInterval(fetchData, pollingInterval);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [pollingInterval, fetchData]);

  return {
    data,
    isLoading,
    error,
    refetch: fetchData,
    isConnected,
    lastUpdated,
  };
}

export default useBeamDashboard;
