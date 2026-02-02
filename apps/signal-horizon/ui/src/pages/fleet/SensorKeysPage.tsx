/**
 * Sensor Keys Page
 *
 * API key management for sensor authentication including
 * key generation, rotation, and revocation.
 */

import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Key, Plus, RotateCw, Trash2, Copy, Check, AlertTriangle, Clock, Shield } from 'lucide-react';
import { MetricCard } from '../../components/fleet';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

interface SensorKey {
  id: string;
  name: string;
  keyPrefix: string;
  sensorId: string;
  sensor?: {
    id: string;
    name: string;
    connectionState: string;
  };
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  permissions: string[];
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  lastRotatedAt: string | null;
}

// KeyActivity interface for potential future use
// interface KeyActivity {
//   id: string;
//   action: 'created' | 'rotated' | 'revoked';
//   keyName: string;
//   timestamp: string;
//   performedBy: string;
// }

interface NewKeyRequest {
  name: string;
  sensorId: string;
  expiresIn?: number; // days
  permissions: string[];
}

export function SensorKeysPage(): React.ReactElement {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState<string | null>(null);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [sortColumn, setSortColumn] = useState<keyof SensorKey>('createdAt');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');

  const queryClient = useQueryClient();

  // Fetch keys
  const { data: keysData, isLoading, error } = useQuery({
    queryKey: ['sensor-keys'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/management/keys`);
      if (!response.ok) throw new Error('Failed to fetch keys');
      return response.json();
    },
  });

  const keys: SensorKey[] = keysData?.keys || [];

  // Fetch sensors for dropdown
  const { data: sensorsData } = useQuery({
    queryKey: ['sensors-list'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/fleet/sensors`);
      if (!response.ok) throw new Error('Failed to fetch sensors');
      return response.json();
    },
  });

  const sensors = sensorsData?.sensors || [];

  // Generate key mutation
  const generateMutation = useMutation({
    mutationFn: async (request: NewKeyRequest) => {
      const response = await fetch(`${API_BASE}/management/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      if (!response.ok) throw new Error('Failed to generate key');
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['sensor-keys'] });
      setGeneratedKey(data.key);
    },
  });

  // Rotate key mutation
  const rotateMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const response = await fetch(`${API_BASE}/management/keys/${keyId}/rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!response.ok) throw new Error('Failed to rotate key');
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['sensor-keys'] });
      setGeneratedKey(data.key);
    },
  });

  // Revoke key mutation
  const revokeMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const response = await fetch(`${API_BASE}/management/keys/${keyId}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error('Failed to revoke key');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sensor-keys'] });
      setKeyToRevoke(null);
    },
  });

  // Calculate stats
  const stats = useMemo(() => {
    const total = keys.length;
    const active = keys.filter((k) => k.status === 'ACTIVE').length;
    const expired = keys.filter((k) => k.status === 'EXPIRED').length;
    const expiringSoon = keys.filter((k) => {
      if (!k.expiresAt || k.status !== 'ACTIVE') return false;
      const daysLeft = Math.floor((new Date(k.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      return daysLeft <= 30 && daysLeft > 0;
    }).length;
    return { total, active, expired, expiringSoon };
  }, [keys]);

  // Sort keys
  const sortedKeys = useMemo(() => {
    return [...keys].sort((a, b) => {
      const aVal = a[sortColumn];
      const bVal = b[sortColumn];
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;
      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      }
      return aVal < bVal ? 1 : -1;
    });
  }, [keys, sortColumn, sortDirection]);

  const handleSort = (column: keyof SensorKey) => {
    if (sortColumn === column) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const handleCopyKey = async () => {
    if (generatedKey) {
      await navigator.clipboard.writeText(generatedKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusBadge = (status: SensorKey['status']) => {
    const styles = {
      ACTIVE: 'bg-green-500/10 text-green-400 border-green-500/30',
      EXPIRED: 'bg-red-500/10 text-red-400 border-red-500/30',
      REVOKED: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
    };
    return (
      <span className={`px-2 py-1 text-xs font-medium rounded border ${styles[status]}`}>
        {status}
      </span>
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-400">Loading API keys...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400">
          Failed to load API keys. Please try again.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">API Key Management</h1>
          <p className="text-gray-400 mt-1">Manage sensor authentication keys and permissions</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Generate New Key
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Keys"
          value={stats.total}
          icon={<Key className="w-6 h-6" />}
          trend={{ value: 0, label: 'All API keys' }}
        />
        <MetricCard
          label="Active Keys"
          value={stats.active}
          icon={<Shield className="w-6 h-6" />}
          trend={{ value: 0, label: 'Currently valid' }}
        />
        <MetricCard
          label="Expired Keys"
          value={stats.expired}
          icon={<Clock className="w-6 h-6" />}
          trend={{ value: 0, label: 'Need rotation' }}
        />
        <MetricCard
          label="Expiring Soon"
          value={stats.expiringSoon}
          icon={<AlertTriangle className="w-6 h-6" />}
          trend={{ value: 0, label: 'Within 30 days' }}
        />
      </div>

      {/* Keys Table */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-700/50">
              <tr>
                <th
                  className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-white"
                  onClick={() => handleSort('name')}
                >
                  Name {sortColumn === 'name' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Sensor
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Key ID
                </th>
                <th
                  className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-white"
                  onClick={() => handleSort('createdAt')}
                >
                  Created {sortColumn === 'createdAt' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-white"
                  onClick={() => handleSort('expiresAt')}
                >
                  Expires {sortColumn === 'expiresAt' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-white"
                  onClick={() => handleSort('status')}
                >
                  Status {sortColumn === 'status' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Last Used
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {sortedKeys.map((key) => (
                <tr key={key.id} className="hover:bg-gray-700/30">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-white">{key.name}</div>
                    {key.permissions.length > 0 && (
                      <div className="text-xs text-gray-400">{key.permissions.join(', ')}</div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {key.sensor?.name || 'All Sensors'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <code className="text-xs font-mono text-gray-400 bg-gray-700 px-2 py-1 rounded">
                      {key.keyPrefix}...
                    </code>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {formatDate(key.createdAt)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {formatDate(key.expiresAt)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">{getStatusBadge(key.status)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {formatDate(key.lastUsedAt)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm space-x-2">
                    {key.status === 'ACTIVE' && (
                      <>
                        <button
                          onClick={() => rotateMutation.mutate(key.id)}
                          disabled={rotateMutation.isPending}
                          className="text-blue-400 hover:text-blue-300 disabled:opacity-50"
                          title="Rotate key"
                        >
                          <RotateCw className="w-4 h-4 inline" />
                        </button>
                        <button
                          onClick={() => setKeyToRevoke(key.id)}
                          className="text-red-400 hover:text-red-300"
                          title="Revoke key"
                        >
                          <Trash2 className="w-4 h-4 inline" />
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {sortedKeys.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-6 py-8 text-center text-gray-400">
                    No API keys found. Click "Generate New Key" to create one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Generate Key Modal */}
      {isModalOpen && (
        <GenerateKeyModal
          sensors={sensors}
          onClose={() => {
            setIsModalOpen(false);
            setGeneratedKey(null);
          }}
          onGenerate={(req) => generateMutation.mutate(req)}
          isGenerating={generateMutation.isPending}
          generatedKey={generatedKey}
          onCopyKey={handleCopyKey}
          copiedKey={copiedKey}
        />
      )}

      {/* Generated Key Display (after rotation) */}
      {generatedKey && !isModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-white mb-4">Key Rotated Successfully</h3>
            <p className="text-sm text-gray-400 mb-4">
              Save this key securely. It won't be shown again.
            </p>
            <div className="bg-gray-900 border border-gray-700 rounded p-3 mb-4">
              <code className="text-xs font-mono text-green-400 break-all">{generatedKey}</code>
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={handleCopyKey}
                className="flex items-center gap-2 px-4 py-2 text-gray-300 hover:text-white"
              >
                {copiedKey ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copiedKey ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={() => setGeneratedKey(null)}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Confirmation Modal */}
      {keyToRevoke && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-white mb-2">Revoke API Key</h3>
            <p className="text-sm text-gray-400 mb-6">
              Are you sure you want to revoke this API key? This action cannot be undone and will
              immediately invalidate the key.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setKeyToRevoke(null)}
                disabled={revokeMutation.isPending}
                className="px-4 py-2 text-gray-300 hover:text-white disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={() => revokeMutation.mutate(keyToRevoke)}
                disabled={revokeMutation.isPending}
                className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
              >
                {revokeMutation.isPending ? 'Revoking...' : 'Revoke Key'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Generate Key Modal Component
function GenerateKeyModal({
  sensors,
  onClose,
  onGenerate,
  isGenerating,
  generatedKey,
  onCopyKey,
  copiedKey,
}: {
  sensors: Array<{ id: string; name: string }>;
  onClose: () => void;
  onGenerate: (req: NewKeyRequest) => void;
  isGenerating: boolean;
  generatedKey: string | null;
  onCopyKey: () => void;
  copiedKey: boolean;
}) {
  const [name, setName] = useState('');
  const [sensorId, setSensorId] = useState('');
  const [expiresIn, setExpiresIn] = useState('90');
  const [permissions, setPermissions] = useState<string[]>(['read:signals', 'write:signals']);

  const availablePermissions = [
    { id: 'read:signals', label: 'Read Signals' },
    { id: 'write:signals', label: 'Write Signals' },
    { id: 'read:config', label: 'Read Configuration' },
    { id: 'write:config', label: 'Write Configuration' },
    { id: 'admin', label: 'Admin Access' },
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!sensorId) return;
    onGenerate({
      name,
      sensorId,
      expiresIn: expiresIn === 'never' ? undefined : parseInt(expiresIn),
      permissions,
    });
  };

  const togglePermission = (id: string) => {
    setPermissions((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-md w-full mx-4">
        {generatedKey ? (
          <>
            <h3 className="text-lg font-semibold text-white mb-4">API Key Generated</h3>
            <p className="text-sm text-gray-400 mb-4">
              Save this key securely. It won't be shown again.
            </p>
            <div className="bg-gray-900 border border-gray-700 rounded p-3 mb-4">
              <code className="text-xs font-mono text-green-400 break-all">{generatedKey}</code>
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={onCopyKey}
                className="flex items-center gap-2 px-4 py-2 text-gray-300 hover:text-white"
              >
                {copiedKey ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copiedKey ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Done
              </button>
            </div>
          </>
        ) : (
          <>
            <h3 className="text-lg font-semibold text-white mb-4">Generate New API Key</h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-white mb-1">Key Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g., Production API Key"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-white mb-1">Sensor</label>
                <select
                  value={sensorId}
                  onChange={(e) => setSensorId(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select a sensor</option>
                  {sensors.map((sensor) => (
                    <option key={sensor.id} value={sensor.id}>
                      {sensor.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-white mb-1">Expiration</label>
                <select
                  value={expiresIn}
                  onChange={(e) => setExpiresIn(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="30">30 days</option>
                  <option value="90">90 days</option>
                  <option value="180">180 days</option>
                  <option value="365">1 year</option>
                  <option value="never">Never</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-white mb-2">Permissions</label>
                <div className="space-y-2">
                  {availablePermissions.map((perm) => (
                    <label key={perm.id} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={permissions.includes(perm.id)}
                        onChange={() => togglePermission(perm.id)}
                        className="w-4 h-4 text-blue-600 border-gray-600 rounded focus:ring-blue-500"
                      />
                      <span className="text-sm text-white">{perm.label}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={isGenerating}
                  className="px-4 py-2 text-gray-300 hover:text-white disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isGenerating || !name || !sensorId || permissions.length === 0}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isGenerating ? 'Generating...' : 'Generate Key'}
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

export default SensorKeysPage;
