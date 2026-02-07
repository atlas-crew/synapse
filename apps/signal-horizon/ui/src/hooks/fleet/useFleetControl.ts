/**
 * useFleetControl Hook
 *
 * Manages fleet-wide operations including batch service control,
 * registration tokens, and global configuration reloads.
 */

import { useMutation } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export type FleetControlCommand = 'reload' | 'restart' | 'shutdown' | 'drain' | 'resume';

interface BatchControlRequest {
  command: FleetControlCommand;
  sensorIds: string[];
  reason?: string;
}

interface BatchControlResult {
  command: FleetControlCommand;
  results: Array<{
    sensorId: string;
    sensorName: string;
    success: boolean;
    message: string;
    state: string;
  }>;
  summary: {
    total: number;
    success: number;
    failure: number;
  };
}

async function executeBatchControl({ command, sensorIds, reason }: BatchControlRequest): Promise<BatchControlResult> {
  const response = await fetch(`${API_BASE}/fleet-control/batch/control/${command}`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ sensorIds, reason }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || errorData.error || 'Failed to execute batch command');
  }

  return response.json();
}

async function revokeAllTokens(): Promise<{ epoch: number }> {
  const response = await fetch(`${API_BASE}/auth/revoke-all`, {
    method: 'POST',
    headers: authHeaders,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || errorData.error || 'Failed to revoke all tokens');
  }

  return response.json();
}

export function useFleetControl() {
  const batchMutation = useMutation({
    mutationFn: executeBatchControl,
  });

  const revokeAllMutation = useMutation({
    mutationFn: revokeAllTokens,
  });

  return {
    executeBatchControl: batchMutation.mutateAsync,
    isExecutingBatch: batchMutation.isPending,
    batchResult: batchMutation.data || null,
    batchError: batchMutation.error as Error | null,

    revokeAllTokens: revokeAllMutation.mutateAsync,
    isRevokingAll: revokeAllMutation.isPending,
    revokeResult: revokeAllMutation.data || null,
    revokeError: revokeAllMutation.error as Error | null,
  };
}

export default useFleetControl;
