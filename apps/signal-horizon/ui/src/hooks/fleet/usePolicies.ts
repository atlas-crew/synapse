/**
 * usePolicies Hook
 *
 * Manages global security policy templates.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string | null;
  severity: 'strict' | 'standard' | 'dev';
  config: Record<string, any>;
  isActive: boolean;
  isDefault: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
}

async function fetchPolicies(): Promise<PolicyTemplate[]> {
  const response = await fetch(`${API_BASE}/fleet/policies`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch policy templates');
  const data = await response.json();
  return data.templates || [];
}

async function fetchDefaults(): Promise<PolicyTemplate[]> {
  const response = await fetch(`${API_BASE}/fleet/policies/defaults`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch default policy templates');
  const data = await response.json();
  return data.templates || [];
}

export function usePolicies() {
  const queryClient = useQueryClient();

  const policiesQuery = useQuery({
    queryKey: ['fleet', 'policies'],
    queryFn: fetchPolicies,
  });

  const defaultsQuery = useQuery({
    queryKey: ['fleet', 'policies', 'defaults'],
    queryFn: fetchDefaults,
  });

  return {
    policies: policiesQuery.data || [],
    isLoading: policiesQuery.isLoading,
    error: policiesQuery.error as Error | null,
    defaults: defaultsQuery.data || [],
    isDefaultsLoading: defaultsQuery.isLoading,
    refresh: () => queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] }),
  };
}

export default usePolicies;
