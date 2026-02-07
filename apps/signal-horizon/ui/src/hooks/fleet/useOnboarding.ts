/**
 * useOnboarding Hook
 *
 * Manages sensor provisioning and registration tokens.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export interface RegistrationToken {
  id: string;
  name: string;
  tokenPrefix: string;
  status: 'ACTIVE' | 'EXPIRED' | 'EXHAUSTED' | 'REVOKED';
  maxUses: number;
  usedCount: number;
  remainingUses: number;
  expiresAt: string | null;
  createdAt: string;
  token?: string; // Only present immediately after creation
}

export interface OnboardingStats {
  pendingApprovals: number;
  activeTokens: number;
  registrationsLast7Days: number;
}

async function fetchTokens(): Promise<RegistrationToken[]> {
  const response = await fetch(`${API_BASE}/onboarding/tokens`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch registration tokens');
  const data = await response.json();
  return data.tokens || [];
}

async function fetchStats(): Promise<OnboardingStats> {
  const response = await fetch(`${API_BASE}/onboarding/stats`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch onboarding stats');
  return response.json();
}

async function createToken(name: string): Promise<RegistrationToken> {
  const response = await fetch(`${API_BASE}/onboarding/tokens`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ name, maxUses: 10, expiresIn: 30 }), // Default to 10 uses, 30 days
  });
  if (!response.ok) throw new Error('Failed to create token');
  return response.json();
}

export function useOnboarding() {
  const queryClient = useQueryClient();

  const tokensQuery = useQuery({
    queryKey: ['onboarding', 'tokens'],
    queryFn: fetchTokens,
  });

  const statsQuery = useQuery({
    queryKey: ['onboarding', 'stats'],
    queryFn: fetchStats,
  });

  const createTokenMutation = useMutation({
    mutationFn: createToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['onboarding'] });
    },
  });

  return {
    tokens: tokensQuery.data || [],
    isLoadingTokens: tokensQuery.isLoading,
    stats: statsQuery.data || { pendingApprovals: 0, activeTokens: 0, registrationsLast7Days: 0 },
    isLoadingStats: statsQuery.isLoading,
    createToken: createTokenMutation.mutateAsync,
    isCreatingToken: createTokenMutation.isPending,
  };
}

export default useOnboarding;
