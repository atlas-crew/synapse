import { type LucideIcon } from 'lucide-react';

// ======================== API Config ========================

export const API_BASE = import.meta.env.VITE_API_URL || '';
export const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';

export const authHeaders = {
  Authorization: `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

// ======================== API Functions ========================

export async function fetchSensorDetail(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch sensor details');
  return response.json();
}

export async function fetchSystemInfo(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/system`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch system info');
  return response.json();
}

export async function fetchPerformance(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/performance`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch performance');
  return response.json();
}

export async function fetchNetwork(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/network`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch network');
  return response.json();
}

export async function fetchProcesses(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/processes`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch processes');
  return response.json();
}

export async function runDiagnostics(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/diagnostics/run`, {
    method: 'POST',
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to run diagnostics');
  return response.json();
}

export async function fetchKernelConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config?section=kernel`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch kernel config');
  return response.json();
}

export async function updateKernelConfig(id: string, params: Record<string, string>, persist: boolean) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config`, {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify({
      section: 'kernel',
      config: { params, persist },
    }),
  });
  if (!response.ok) throw new Error('Failed to update kernel config');
  return response.json();
}

export async function fetchSystemConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch system config');
  return response.json();
}

export async function fetchCommandHistory(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/commands?limit=100&offset=0`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch command history');
  const data = await response.json();
  const commands = (data?.commands || []).filter((command: any) => command.sensorId === id);
  return { ...data, commands };
}

export async function fetchPingoraConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch Pingora config');
  return response.json();
}

export async function updatePingoraConfig(id: string, config: any) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(config),
  });
  if (!response.ok) throw new Error('Failed to update Pingora config');
  return response.json();
}

export async function runPingoraAction(id: string, action: 'test' | 'reload' | 'restart') {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/actions/pingora`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ action }),
  });
  if (!response.ok) throw new Error('Failed to run Pingora action');
  return response.json();
}

// ======================== Helper Components ========================

export function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <dt className="text-ink-secondary">{label}</dt>
      <dd className="text-ink-primary font-mono text-xs">{value}</dd>
    </div>
  );
}

export function ActionButton({ icon: Icon, label, onClick }: { icon: LucideIcon; label: string; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className="group flex items-center gap-2 px-4 py-3 bg-surface-subtle border border-border-subtle hover:border-ac-blue/60 hover:bg-surface-card transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
    >
      <Icon className="w-4 h-4 text-ac-blue group-hover:text-ac-magenta transition-colors" />
      <span className="text-xs uppercase tracking-[0.2em] text-ink-secondary group-hover:text-ink-primary">
        {label}
      </span>
    </button>
  );
}

// ======================== Helper Functions ========================

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

// ======================== Types ========================

export type TabType = 'overview' | 'performance' | 'network' | 'processes' | 'logs' | 'configuration' | 'remote-shell' | 'files';
