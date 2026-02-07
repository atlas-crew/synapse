/**
 * usePolicies Hook
 *
 * Manages global security policy templates.
 */

import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY =
  import.meta.env.VITE_API_KEY ||
  import.meta.env.VITE_HORIZON_API_KEY ||
  'dev-dashboard-key';
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

type PolicyTemplateInput = {
  name: string;
  description?: string;
  severity: PolicyTemplate['severity'];
  config: Record<string, any>;
};

async function createPolicyTemplate(input: PolicyTemplateInput) {
  const response = await fetch(`${API_BASE}/fleet/policies`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(input),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.message || body?.error || 'Failed to create policy template');
  }
  return response.json();
}

async function updatePolicyTemplate(params: {
  id: string;
  input: Partial<PolicyTemplateInput>;
}) {
  const response = await fetch(`${API_BASE}/fleet/policies/${params.id}`, {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify(params.input),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.message || body?.error || 'Failed to update policy template');
  }
  return response.json();
}

async function deletePolicyTemplate(id: string) {
  const response = await fetch(`${API_BASE}/fleet/policies/${id}`, {
    method: 'DELETE',
    headers: authHeaders,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.message || body?.error || 'Failed to delete policy template');
  }
  return true;
}

async function clonePolicyTemplate(params: { id: string; name: string }) {
  const response = await fetch(`${API_BASE}/fleet/policies/${params.id}/clone`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ name: params.name }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.message || body?.error || 'Failed to clone policy template');
  }
  return response.json();
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

  const createMutation = useMutation({
    mutationFn: createPolicyTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies', 'defaults'] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: updatePolicyTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies', 'defaults'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicyTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies', 'defaults'] });
    },
  });

  const cloneMutation = useMutation({
    mutationFn: clonePolicyTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['fleet', 'policies', 'defaults'] });
    },
  });

  return {
    policies: policiesQuery.data || [],
    isLoading: policiesQuery.isLoading,
    error: policiesQuery.error as Error | null,
    defaults: defaultsQuery.data || [],
    isDefaultsLoading: defaultsQuery.isLoading,
    refresh: () => queryClient.invalidateQueries({ queryKey: ['fleet', 'policies'] }),

    createTemplate: createMutation.mutateAsync,
    isCreating: createMutation.isPending,
    updateTemplate: updateMutation.mutateAsync,
    isUpdating: updateMutation.isPending,
    deleteTemplate: deleteMutation.mutateAsync,
    isDeleting: deleteMutation.isPending,
    cloneTemplate: cloneMutation.mutateAsync,
    isCloning: cloneMutation.isPending,
  };
}

export default usePolicies;
