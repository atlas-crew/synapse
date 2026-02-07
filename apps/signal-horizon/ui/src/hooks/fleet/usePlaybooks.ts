/**
 * usePlaybooks Hook
 *
 * Manages automation playbooks for Signal Horizon.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  triggerType: 'MANUAL' | 'SIGNAL_SEVERITY' | 'SIGNAL_TYPE';
  triggerValue?: string;
  steps: Array<{
    id: string;
    type: 'manual' | 'command' | 'notification';
    title: string;
    description?: string;
    config?: Record<string, any>;
  }>;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

async function fetchPlaybooks(): Promise<Playbook[]> {
  const response = await fetch(`${API_BASE}/playbooks`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch playbooks');
  const data = await response.json();
  return data.playbooks || [];
}

export function usePlaybooks() {
  const queryClient = useQueryClient();

  const playbooksQuery = useQuery({
    queryKey: ['playbooks'],
    queryFn: fetchPlaybooks,
  });

  return {
    playbooks: playbooksQuery.data || [],
    isLoading: playbooksQuery.isLoading,
    error: playbooksQuery.error as Error | null,
    refresh: () => queryClient.invalidateQueries({ queryKey: ['playbooks'] }),
  };
}

export default usePlaybooks;
