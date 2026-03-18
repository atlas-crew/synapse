/**
 * Sensor Keys Page
 *
 * API key management for sensor authentication including
 * key generation, rotation, and revocation.
 */

import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Key,
  Plus,
  RotateCw,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  Clock,
  Shield,
} from 'lucide-react';
import { MetricCard } from '../../components/fleet';
import { apiFetch } from '../../lib/api';
import { 
  Alert,
  Modal, 
  SectionHeader, 
  colors,
  Box,
  Button,
  Stack,
  Text,
  Input,
  Select,
  StatusBadge
} from '@/ui';

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
  const {
    data: keysData,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['sensor-keys'],
    queryFn: async () => {
      return apiFetch('/management/keys');
    },
  });

  const keys: SensorKey[] = keysData?.keys || [];

  // Fetch sensors for dropdown
  const { data: sensorsData } = useQuery({
    queryKey: ['sensors-list'],
    queryFn: async () => {
      return apiFetch('/fleet/sensors');
    },
  });

  const sensors = sensorsData?.sensors || [];

  // Generate key mutation
  const generateMutation = useMutation({
    mutationFn: async (request: NewKeyRequest) => {
      return apiFetch('/management/keys', { method: 'POST', body: request });
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['sensor-keys'] });
      setGeneratedKey(data.key);
    },
  });

  // Rotate key mutation
  const rotateMutation = useMutation({
    mutationFn: async (keyId: string) => {
      return apiFetch(`/management/keys/${keyId}/rotate`, { method: 'POST', body: {} });
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['sensor-keys'] });
      setGeneratedKey(data.key);
    },
  });

  // Revoke key mutation
  const revokeMutation = useMutation({
    mutationFn: async (keyId: string) => {
      return apiFetch(`/management/keys/${keyId}`, { method: 'DELETE' });
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
      const daysLeft = Math.floor(
        (new Date(k.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24),
      );
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
    const statusType = status === 'ACTIVE' ? 'success' : status === 'EXPIRED' ? 'error' : 'info';
    return <StatusBadge status={statusType} variant="subtle" size="sm">{status}</StatusBadge>;
  };

  if (isLoading) {
    return (
      <Box p="xl" style={{ textAlign: 'center' }}>
        <Text variant="body" color="secondary">Loading API keys...</Text>
      </Box>
    );
  }

  if (error) {
    return (
      <Box p="xl">
        <Alert status="error" title="Load Error">
          Failed to load API keys. Please try again.
        </Alert>
      </Box>
    );
  }

  return (
    <Box p="xl">
      <Stack gap="xl">
        {/* Header */}
        <Box flex direction="row" align="center" justify="space-between">
          <SectionHeader
            title="API Key Management"
            description="Manage sensor authentication keys and permissions"
            size="h1"
            titleStyle={{ fontSize: '20px', lineHeight: '28px' }}
          />
          <Button
            onClick={() => setIsModalOpen(true)}
            icon={<Plus size={16} aria-hidden="true" />}
            size="lg"
          >
            Generate New Key
          </Button>
        </Box>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            label="Total Keys"
            value={stats.total}
            icon={<Key className="w-6 h-6" />}
          />
          <MetricCard
            label="Active Keys"
            value={stats.active}
            icon={<Shield className="w-6 h-6" />}
          />
          <MetricCard
            label="Expired Keys"
            value={stats.expired}
            icon={<Clock className="w-6 h-6" />}
          />
          <MetricCard
            label="Expiring Soon"
            value={stats.expiringSoon}
            icon={<AlertTriangle className="w-6 h-6" />}
          />
        </div>

        {/* Keys Table */}
        <Box bg="card" border="subtle">
          <Box style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <caption className="sr-only">Sensor API keys with expiration and usage status</caption>
              <thead>
                <tr>
                  <th
                    style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)', cursor: 'pointer' }}
                    onClick={() => handleSort('name')}
                  >
                    <Stack direction="row" align="center" gap="xs">
                      <Text variant="label" color="secondary" noMargin>Name</Text>
                      {sortColumn === 'name' && <Text variant="caption" color="secondary" noMargin>{sortDirection === 'asc' ? '↑' : '↓'}</Text>}
                    </Stack>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Sensor</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Key ID</Text>
                  </th>
                  <th
                    style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)', cursor: 'pointer' }}
                    onClick={() => handleSort('createdAt')}
                  >
                    <Stack direction="row" align="center" gap="xs">
                      <Text variant="label" color="secondary" noMargin>Created</Text>
                      {sortColumn === 'createdAt' && <Text variant="caption" color="secondary" noMargin>{sortDirection === 'asc' ? '↑' : '↓'}</Text>}
                    </Stack>
                  </th>
                  <th
                    style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)', cursor: 'pointer' }}
                    onClick={() => handleSort('expiresAt')}
                  >
                    <Stack direction="row" align="center" gap="xs">
                      <Text variant="label" color="secondary" noMargin>Expires</Text>
                      {sortColumn === 'expiresAt' && <Text variant="caption" color="secondary" noMargin>{sortDirection === 'asc' ? '↑' : '↓'}</Text>}
                    </Stack>
                  </th>
                  <th
                    style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)', cursor: 'pointer' }}
                    onClick={() => handleSort('status')}
                  >
                    <Stack direction="row" align="center" gap="xs">
                      <Text variant="label" color="secondary" noMargin>Status</Text>
                      {sortColumn === 'status' && <Text variant="caption" color="secondary" noMargin>{sortDirection === 'asc' ? '↑' : '↓'}</Text>}
                    </Stack>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Last Used</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Actions</Text>
                  </th>
                </tr>
              </thead>
              <tbody>
                {sortedKeys.map((key) => (
                  <tr key={key.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" weight="medium" noMargin>{key.name}</Text>
                      {key.permissions.length > 0 && (
                        <Text variant="caption" color="secondary" noMargin>{key.permissions.join(', ')}</Text>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>{key.sensor?.name || 'All Sensors'}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="code" noMargin>{key.keyPrefix}...</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>{formatDate(key.createdAt)}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>{formatDate(key.expiresAt)}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>{getStatusBadge(key.status)}</td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>{formatDate(key.lastUsedAt)}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Stack direction="row" gap="sm">
                        {key.status === 'ACTIVE' && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => rotateMutation.mutate(key.id)}
                              disabled={rotateMutation.isPending}
                              title="Rotate key"
                              icon={<RotateCw size={14} />}
                            />
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setKeyToRevoke(key.id)}
                              title="Revoke key"
                              icon={<Trash2 size={14} style={{ color: colors.red }} />}
                            />
                          </>
                        )}
                      </Stack>
                    </td>
                  </tr>
                ))}
                {sortedKeys.length === 0 && (
                  <tr>
                    <td colSpan={8} style={{ padding: '32px', textAlign: 'center' }}>
                      <Text variant="body" color="secondary" noMargin>
                        No API keys found. Click "Generate New Key" to create one.
                      </Text>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Box>
        </Box>

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
          <Modal open onClose={() => setGeneratedKey(null)} size="520px" title="Key Rotated Successfully">
            <Stack gap="lg">
              <Text variant="body" color="secondary">Save this key securely. It won't be shown again.</Text>
              <Box bg="bg" border="subtle" p="md">
                <Text variant="code" weight="medium" style={{ color: colors.green, wordBreak: 'break-all' }}>
                  {generatedKey}
                </Text>
              </Box>
              <Stack direction="row" gap="md" justify="end">
                <Button
                  variant="outlined"
                  onClick={handleCopyKey}
                  icon={copiedKey ? <Check size={14} /> : <Copy size={14} />}
                >
                  {copiedKey ? 'Copied!' : 'Copy'}
                </Button>
                <Button onClick={() => setGeneratedKey(null)}>
                  Done
                </Button>
              </Stack>
            </Stack>
          </Modal>
        )}

        {/* Revoke Confirmation Modal */}
        {keyToRevoke && (
          <Modal open onClose={() => setKeyToRevoke(null)} size="520px" title="Revoke API Key">
            <Stack gap="xl">
              <Text variant="body" color="secondary">
                Are you sure you want to revoke this API key? This action cannot be undone and will
                immediately invalidate the key.
              </Text>
              <Stack direction="row" gap="md" justify="end">
                <Button
                  variant="outlined"
                  onClick={() => setKeyToRevoke(null)}
                  disabled={revokeMutation.isPending}
                >
                  Cancel
                </Button>
                <Button
                  onClick={() => revokeMutation.mutate(keyToRevoke)}
                  disabled={revokeMutation.isPending}
                  style={{ background: colors.red, borderColor: colors.red }}
                >
                  {revokeMutation.isPending ? 'Revoking...' : 'Revoke Key'}
                </Button>
              </Stack>
            </Stack>
          </Modal>
        )}
      </Stack>
    </Box>
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
    <Modal
      open
      onClose={onClose}
      size="520px"
      title={generatedKey ? 'API Key Generated' : 'Generate New API Key'}
    >
      {generatedKey ? (
        <Stack gap="lg">
          <Text variant="body" color="secondary">Save this key securely. It won't be shown again.</Text>
          <Box bg="bg" border="subtle" p="md">
            <Text variant="code" weight="medium" style={{ color: colors.green, wordBreak: 'break-all' }}>
              {generatedKey}
            </Text>
          </Box>
          <Stack direction="row" gap="md" justify="end">
            <Button
              variant="outlined"
              onClick={onCopyKey}
              icon={copiedKey ? <Check size={14} /> : <Copy size={14} />}
            >
              {copiedKey ? 'Copied!' : 'Copy'}
            </Button>
            <Button onClick={onClose}>
              Done
            </Button>
          </Stack>
        </Stack>
      ) : (
        <form onSubmit={handleSubmit}>
          <Stack gap="lg">
            <Input
              label="Key Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              placeholder="e.g., Production API Key"
              size="md"
            />
            <Select
              label="Sensor"
              value={sensorId}
              onChange={(e) => setSensorId(e.target.value)}
              required
              options={[
                { value: '', label: 'Select a sensor' },
                ...sensors.map(s => ({ value: s.id, label: s.name }))
              ]}
              size="md"
            />
            <Select
              label="Expiration"
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              options={[
                { value: '30', label: '30 days' },
                { value: '90', label: '90 days' },
                { value: '180', label: '180 days' },
                { value: '365', label: '1 year' },
                { value: 'never', label: 'Never' },
              ]}
              size="md"
            />
            <Box>
              <Text variant="label" color="secondary" style={{ marginBottom: '8px' }}>Permissions</Text>
              <Stack gap="sm">
                {availablePermissions.map((perm) => (
                  <Stack key={perm.id} as="label" direction="row" align="center" gap="md" style={{ cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={permissions.includes(perm.id)}
                      onChange={() => togglePermission(perm.id)}
                      className="w-4 h-4"
                      style={{ accentColor: 'var(--ac-blue)' }}
                    />
                    <Text variant="body" noMargin>{perm.label}</Text>
                  </Stack>
                ))}
              </Stack>
            </Box>
            <Stack direction="row" gap="md" justify="end" style={{ marginTop: '12px' }}>
              <Button
                variant="outlined"
                onClick={onClose}
                disabled={isGenerating}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={isGenerating || !name || !sensorId || permissions.length === 0}
              >
                {isGenerating ? 'Generating...' : 'Generate Key'}
              </Button>
            </Stack>
          </Stack>
        </form>
      )}
    </Modal>
  );
}

export default SensorKeysPage;
