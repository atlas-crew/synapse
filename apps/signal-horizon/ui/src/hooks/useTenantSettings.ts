/**
 * useTenantSettings Hook
 *
 * Manages tenant-level configuration including sharing preferences,
 * data consent, and withdrawal requests.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

// =============================================================================
// Type Definitions
// =============================================================================

export type SharingPreference = 
  | 'CONTRIBUTE_AND_RECEIVE'
  | 'RECEIVE_ONLY'
  | 'CONTRIBUTE_ONLY'
  | 'ISOLATED';

export interface TenantSettings {
  data: {
    sharingPreference: SharingPreference;
  };
  metadata: {
    changedAt: string;
    changedBy: string;
    consent: {
      status: 'acknowledged' | 'withdrawn' | 'not_given';
      acknowledgedAt: string | null;
    };
    schemaVersion: string;
  };
}

export interface ConsentRequest {
  consentType: 'BLOCKLIST_SHARING';
  acknowledged: boolean;
  version?: string;
}

export interface WithdrawalRequest {
  since?: string;
  type: 'CONTRIBUTION' | 'GDPR_ERASURE';
  reason?: string;
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchSettings(): Promise<TenantSettings> {
  const response = await fetch(`${API_BASE}/tenant/settings`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch tenant settings');
  return response.json();
}

async function updateSettings(
  preference: SharingPreference,
  idempotencyKey: string
): Promise<TenantSettings> {
  const response = await fetch(`${API_BASE}/tenant/settings`, {
    method: 'PATCH',
    headers: {
      ...authHeaders,
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify({ sharingPreference: preference }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || errorData.error || 'Failed to update settings');
  }
  return response.json();
}

async function recordConsent(consent: ConsentRequest): Promise<any> {
  const response = await fetch(`${API_BASE}/tenant/consent`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(consent),
  });
  if (!response.ok) throw new Error('Failed to record consent');
  return response.json();
}

async function requestWithdrawal(request: WithdrawalRequest): Promise<any> {
  const response = await fetch(`${API_BASE}/tenant/withdrawal-request`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(request),
  });
  if (!response.ok) throw new Error('Failed to process withdrawal request');
  return response.json();
}

// =============================================================================
// Main Hook
// =============================================================================

export function useTenantSettings() {
  const queryClient = useQueryClient();

  const settingsQuery = useQuery({
    queryKey: ['tenant', 'settings'],
    queryFn: fetchSettings,
  });

  const updateMutation = useMutation({
    mutationFn: ({ preference, idempotencyKey }: { preference: SharingPreference; idempotencyKey: string }) =>
      updateSettings(preference, idempotencyKey),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant', 'settings'] });
    },
  });

  const consentMutation = useMutation({
    mutationFn: recordConsent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant', 'settings'] });
    },
  });

  const withdrawalMutation = useMutation({
    mutationFn: requestWithdrawal,
  });

  return {
    settings: settingsQuery.data || null,
    isLoading: settingsQuery.isLoading,
    error: settingsQuery.error as Error | null,
    updateSettings: updateMutation.mutateAsync,
    isUpdating: updateMutation.isPending,
    recordConsent: consentMutation.mutateAsync,
    isConsenting: consentMutation.isPending,
    requestWithdrawal: withdrawalMutation.mutateAsync,
    isWithdrawing: withdrawalMutation.isPending,
  };
}

export default useTenantSettings;
