/**
 * useHubConfig Hook
 *
 * Manages Signal Horizon Hub runtime configuration.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export interface HubConfig {
  env: string;
  fleetCommands?: {
    enableToggleChaos: boolean;
    enableToggleMtd: boolean;
  };
  server: {
    port: number;
    host: string;
  };
  database: {
    url: string;
  };
  websocket: {
    sensorPath: string;
    dashboardPath: string;
    heartbeatIntervalMs: number;
    maxSensorConnections: number;
    maxDashboardConnections: number;
  };
  aggregator: {
    batchSize: number;
    batchTimeoutMs: number;
  };
  broadcaster: {
    pushDelayMs: number;
    cacheSize: number;
  };
  logging: {
    level: string;
  };
  riskServer: {
    url: string;
  };
  synapseDirect: {
    url?: string;
    enabled: boolean;
  };
  sensorBridge: {
    enabled: boolean;
    sensorId: string;
    sensorName: string;
    heartbeatIntervalMs: number;
  };
}

async function fetchHubConfig(): Promise<HubConfig> {
  const response = await fetch(`${API_BASE}/management/config`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch hub config');
  return response.json();
}

async function updateHubConfig(updates: Partial<HubConfig>): Promise<any> {
  const response = await fetch(`${API_BASE}/management/config`, {
    method: 'PATCH',
    headers: authHeaders,
    body: JSON.stringify(updates),
  });
  if (!response.ok) throw new Error('Failed to update hub config');
  return response.json();
}

export function useHubConfig() {
  const queryClient = useQueryClient();

  const configQuery = useQuery({
    queryKey: ['hub', 'config'],
    queryFn: fetchHubConfig,
  });

  const updateMutation = useMutation({
    mutationFn: updateHubConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hub', 'config'] });
    },
  });

  return {
    config: configQuery.data || null,
    isLoading: configQuery.isLoading,
    error: configQuery.error as Error | null,
    updateConfig: updateMutation.mutateAsync,
    isUpdating: updateMutation.isPending,
  };
}

export default useHubConfig;
