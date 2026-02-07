/**
 * useBlocklist Hook
 *
 * Manages the global IP blocklist.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
const API_KEY =
  import.meta.env.VITE_API_KEY ||
  import.meta.env.VITE_HORIZON_API_KEY ||
  'dev-dashboard-key';
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

export interface BlocklistEntry {
  id: string;
  blockType: 'IP' | 'IP_RANGE' | 'FINGERPRINT' | 'ASN' | 'USER_AGENT';
  indicator: string;
  reason: string;
  source: 'AUTOMATIC' | 'MANUAL' | 'FLEET_INTEL' | 'EXTERNAL_FEED' | 'WAR_ROOM';
  createdAt: string;
  expiresAt?: string;
  propagationStatus: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'PARTIAL' | 'WITHDRAWN';
  tenantId?: string | null;
}

export interface BlocklistStats {
  totalActive: number;
  manualCount: number;
  autoCount24h: number;
  syncRate: number;
}

function computeStats(entries: BlocklistEntry[]): BlocklistStats {
  const now = Date.now();
  const oneDayAgo = now - 24 * 60 * 60 * 1000;

  const active = entries.filter((e) => {
    if (e.propagationStatus === 'WITHDRAWN') return false;
    if (!e.expiresAt) return true;
    return Date.parse(e.expiresAt) > now;
  });

  const manualCount = active.filter((e) => e.source === 'MANUAL').length;
  const autoCount24h = active.filter((e) => e.source === 'AUTOMATIC' && Date.parse(e.createdAt) > oneDayAgo).length;

  const synced = active.filter((e) => e.propagationStatus === 'COMPLETED' || e.propagationStatus === 'PARTIAL').length;
  const syncRate = active.length > 0 ? Math.round((synced / active.length) * 100) : 100;

  return {
    totalActive: active.length,
    manualCount,
    autoCount24h,
    syncRate,
  };
}

async function fetchEntries(): Promise<BlocklistEntry[]> {
  const response = await fetch(`${API_BASE}/blocklist?limit=500&offset=0`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch blocklist');
  const data = await response.json().catch(() => ({}));
  return Array.isArray(data.entries) ? data.entries : [];
}

async function fetchBlocklistStats(): Promise<BlocklistStats> {
  const entries = await fetchEntries();
  return computeStats(entries);
}

async function addBlock(ip: string, reason: string): Promise<BlocklistEntry> {
  const response = await fetch(`${API_BASE}/blocklist`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      blockType: 'IP',
      indicator: ip,
      reason,
      // Admin Settings is a hub-admin surface; default to fleet-wide.
      fleetWide: true,
    }),
  });
  if (!response.ok) throw new Error('Failed to add block');
  return response.json();
}

export function useBlocklist() {
  const queryClient = useQueryClient();

  const statsQuery = useQuery({
    queryKey: ['blocklist', 'stats'],
    queryFn: fetchBlocklistStats,
  });

  const addBlockMutation = useMutation({
    mutationFn: ({ ip, reason }: { ip: string; reason: string }) => addBlock(ip, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocklist', 'stats'] });
    },
  });

  return {
    stats: statsQuery.data || { totalActive: 0, manualCount: 0, autoCount24h: 0, syncRate: 100 },
    isLoadingStats: statsQuery.isLoading,
    addBlock: addBlockMutation.mutateAsync,
    isAddingBlock: addBlockMutation.isPending,
  };
}

export default useBlocklist;
