/**
 * Sensor Onboarding Page
 *
 * Registration token management and pending sensor approval workflow.
 * Enables zero-touch provisioning with secure token-based registration.
 */

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  Clock,
  Server,
  CheckCircle,
  XCircle,
  UserPlus,
  Globe,
} from 'lucide-react';
import { apiFetch } from '../../lib/api';
import { Button, MetricCard, Modal, PAGE_TITLE_STYLE, Panel, SectionHeader, Stack, colors } from '@/ui';
import { OnboardingWizard } from '../../components/onboarding/OnboardingWizard';

interface RegistrationToken {
  id: string;
  name: string;
  tokenPrefix: string;
  status: 'ACTIVE' | 'EXPIRED' | 'EXHAUSTED' | 'REVOKED';
  maxUses: number;
  usedCount: number;
  remainingUses: number;
  region: string | null;
  expiresAt: string | null;
  createdAt: string;
  createdBy: string;
}

interface PendingSensor {
  id: string;
  name: string;
  hostname: string;
  region: string | null;
  version: string | null;
  os: string | null;
  architecture: string | null;
  publicIp: string | null;
  privateIp: string | null;
  registrationMethod: string;
  registrationToken: string | null;
  createdAt: string;
  lastHeartbeat: string | null;
}

interface NewTokenRequest {
  name: string;
  maxUses: number;
  expiresIn?: number;
  region?: string;
}
const PAGE_HEADER_STYLE = { marginBottom: 0 };
export function OnboardingPage(): React.ReactElement {
  const [activeTab, setActiveTab] = useState<'tokens' | 'pending'>('tokens');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [tokenToRevoke, setTokenToRevoke] = useState<string | null>(null);
  // Note: sensorToProcess reserved for future modal-based approval with confirmation
  const [_sensorToProcess, _setSensorToProcess] = useState<{
    id: string;
    action: 'approve' | 'reject';
  } | null>(null);
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  const queryClient = useQueryClient();

  // Fetch statistics
  const { data: statsData } = useQuery<any>({
    queryKey: ['onboarding-stats'],
    queryFn: async () => {
      return apiFetch('/onboarding/stats');
    },
  });

  // Fetch tokens
  const {
    data: tokensData,
    isLoading: tokensLoading,
    error: tokensError,
  } = useQuery({
    queryKey: ['registration-tokens'],
    queryFn: async () => {
      return apiFetch('/onboarding/tokens');
    },
    enabled: activeTab === 'tokens',
  });

  // Fetch pending sensors
  const {
    data: pendingData,
    isLoading: pendingLoading,
    error: pendingError,
  } = useQuery({
    queryKey: ['pending-sensors'],
    queryFn: async () => {
      return apiFetch('/onboarding/pending');
    },
    enabled: activeTab === 'pending',
  });

  const tokens: RegistrationToken[] = tokensData?.tokens || [];
  const pendingSensors: PendingSensor[] = pendingData?.sensors || [];

  // Generate token mutation
  const generateMutation = useMutation({
    mutationFn: async (request: NewTokenRequest) => {
      return apiFetch('/onboarding/tokens', { method: 'POST', body: request });
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['registration-tokens'] });
      queryClient.invalidateQueries({ queryKey: ['onboarding-stats'] });
      setGeneratedToken(data.token);
    },
  });

  // Revoke token mutation
  const revokeMutation = useMutation({
    mutationFn: async (tokenId: string) => {
      await apiFetch(`/onboarding/tokens/${tokenId}`, { method: 'DELETE' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['registration-tokens'] });
      queryClient.invalidateQueries({ queryKey: ['onboarding-stats'] });
      setTokenToRevoke(null);
    },
  });

  // Approve/reject sensor mutation
  const approvalMutation = useMutation({
    mutationFn: async ({
      sensorId,
      action,
      assignedName,
    }: {
      sensorId: string;
      action: 'approve' | 'reject';
      assignedName?: string;
    }) => {
      return apiFetch(`/onboarding/pending/${sensorId}`, {
        method: 'POST',
        body: { action, assignedName },
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pending-sensors'] });
      queryClient.invalidateQueries({ queryKey: ['onboarding-stats'] });
      _setSensorToProcess(null);
    },
  });

  const handleCopyToken = () => {
    if (generatedToken) {
      navigator.clipboard.writeText(generatedToken);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  const handleCreateToken = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const request: NewTokenRequest = {
      name: formData.get('name') as string,
      maxUses: parseInt(formData.get('maxUses') as string) || 1,
      expiresIn: formData.get('expiresIn')
        ? parseInt(formData.get('expiresIn') as string)
        : undefined,
      region: (formData.get('region') as string) || undefined,
    };
    generateMutation.mutate(request);
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      ACTIVE: 'bg-ac-green/10 text-ac-green border-ac-green/20',
      EXPIRED: 'bg-ac-orange/10 text-ac-orange border-ac-orange/20',
      EXHAUSTED: 'bg-ac-yellow/10 text-ac-yellow border-ac-yellow/20',
      REVOKED: 'bg-ac-red/10 text-ac-red border-ac-red/20',
    };
    return (
      <span
        className={`px-2 py-0.5 text-xs font-medium border ${styles[status] || 'bg-ink-muted/10'}`}
      >
        {status}
      </span>
    );
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '—';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="flex-1 p-6 space-y-6">
      {/* Header */}
      <SectionHeader
        title="Sensor Onboarding"
        description="Manage registration tokens and approve pending sensors"
        size="h1"
        style={PAGE_HEADER_STYLE}
        titleStyle={PAGE_TITLE_STYLE}
        actions={
          <Stack direction="row" gap="sm">
            <Button variant="primary" onClick={() => setIsWizardOpen(true)}>
              <Stack as="span" inline direction="row" align="center" gap="sm">
                <UserPlus className="w-4 h-4" />
                Guided setup
              </Stack>
            </Button>
            <button
              onClick={() => setIsModalOpen(true)}
              className="btn-primary"
            >
              <Stack as="span" inline direction="row" align="center" gap="sm">
                <Plus className="w-4 h-4" />
                New Token
              </Stack>
            </button>
          </Stack>
        }
      />

      <OnboardingWizard open={isWizardOpen} onClose={() => setIsWizardOpen(false)} />

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard
          label="Pending Approvals"
          value={statsData?.pendingApprovals || 0}
          icon={<Clock className="w-5 h-5" />}
          trend={
            statsData?.pendingApprovals > 0 ? { value: 1, label: 'needs attention' } : undefined
          }
        />
        <MetricCard
          label="Active Tokens"
          value={statsData?.activeTokens || 0}
          icon={<Key className="w-5 h-5" />}
        />
        <MetricCard
          label="Registrations (7d)"
          value={statsData?.registrationsLast7Days || 0}
          icon={<UserPlus className="w-5 h-5" />}
        />
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-border-subtle">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('tokens')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'tokens'
                ? 'border-link text-link'
                : 'border-transparent text-ink-secondary hover:text-ink-primary'
            }`}
          >
            <Key className="w-4 h-4 inline-block mr-2" />
            Registration Tokens
          </button>
          <button
            onClick={() => setActiveTab('pending')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'pending'
                ? 'border-link text-link'
                : 'border-transparent text-ink-secondary hover:text-ink-primary'
            }`}
          >
            <Clock className="w-4 h-4 inline-block mr-2" />
            Pending Sensors
            {(statsData?.pendingApprovals || 0) > 0 && (
              <span className="ml-2 px-2 py-0.5 text-xs bg-ac-orange/10 text-ac-orange">
                {statsData.pendingApprovals}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* Registration Tokens Tab */}
      {activeTab === 'tokens' && (
        <Panel tone="default" padding="none" spacing="none" as="div">
          {tokensLoading ? (
            <div className="p-8 text-center text-ink-muted">Loading tokens...</div>
          ) : tokensError ? (
            <div className="p-8 text-center text-ac-red">
              <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
              Failed to load tokens
            </div>
          ) : tokens.length === 0 ? (
            <div className="p-8 text-center text-ink-muted">
              <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No registration tokens yet</p>
              <p className="text-sm mt-1">Create a token to enable sensor registration</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-surface-subtle border-b border-border-subtle">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Name
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Prefix
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Uses
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Region
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Expires
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Created
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-ink-muted uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {tokens.map((token) => (
                  <tr key={token.id} className="hover:bg-surface-subtle/50">
                    <td className="px-4 py-3 text-sm font-medium text-ink-primary">{token.name}</td>
                    <td className="px-4 py-3 text-sm font-mono text-ink-secondary">
                      {token.tokenPrefix}...
                    </td>
                    <td className="px-4 py-3">{getStatusBadge(token.status)}</td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      {token.usedCount} / {token.maxUses}
                      <span className="text-ink-muted ml-1">({token.remainingUses} left)</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">{token.region || '—'}</td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      {formatDate(token.expiresAt)}
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      {formatDate(token.createdAt)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {token.status === 'ACTIVE' && (
                        <button
                          onClick={() => setTokenToRevoke(token.id)}
                          className="btn-ghost p-1.5 text-ac-red hover:bg-ac-red/10"
                          title="Revoke token"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {/* Pending Sensors Tab */}
      {activeTab === 'pending' && (
        <Panel tone="default" padding="none" spacing="none" as="div">
          {pendingLoading ? (
            <div className="p-8 text-center text-ink-muted">Loading pending sensors...</div>
          ) : pendingError ? (
            <div className="p-8 text-center text-ac-red">
              <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
              Failed to load pending sensors
            </div>
          ) : pendingSensors.length === 0 ? (
            <div className="p-8 text-center text-ink-muted">
              <CheckCircle className="w-12 h-12 mx-auto mb-3 opacity-50 text-ac-green" />
              <p>No pending sensors</p>
              <p className="text-sm mt-1">All sensors have been processed</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-surface-subtle border-b border-border-subtle">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Hostname
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    System
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    IP Address
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Region
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-muted uppercase">
                    Registered
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-ink-muted uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {pendingSensors.map((sensor) => (
                  <tr key={sensor.id} className="hover:bg-surface-subtle/50">
                    <td className="px-4 py-3">
                      <Stack direction="row" align="center" gap="sm">
                        <Server className="w-4 h-4 text-ink-muted" />
                        <span className="text-sm font-medium text-ink-primary">
                          {sensor.hostname}
                        </span>
                      </Stack>
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      {sensor.os || 'Unknown'} {sensor.architecture && `(${sensor.architecture})`}
                      {sensor.version && (
                        <span className="text-ink-muted ml-1">v{sensor.version}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-ink-secondary">
                      {sensor.publicIp || sensor.privateIp || '—'}
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      <Globe className="w-3 h-3 inline-block mr-1" />
                      {sensor.region || '—'}
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-secondary">
                      {formatDate(sensor.createdAt)}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        onClick={() =>
                          approvalMutation.mutate({ sensorId: sensor.id, action: 'approve' })
                        }
                        className="btn-ghost p-1.5 text-ac-green hover:bg-ac-green/10"
                        title="Approve sensor"
                        disabled={approvalMutation.isPending}
                      >
                        <CheckCircle className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() =>
                          approvalMutation.mutate({ sensorId: sensor.id, action: 'reject' })
                        }
                        className="btn-ghost p-1.5 text-ac-red hover:bg-ac-red/10"
                        title="Reject sensor"
                        disabled={approvalMutation.isPending}
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {/* Create Token Modal */}
      {isModalOpen && !generatedToken && (
        <Modal open onClose={() => setIsModalOpen(false)} size="520px" title="Create Registration Token">
          <form onSubmit={handleCreateToken} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">Token Name</label>
              <input
                name="name"
                type="text"
                required
                placeholder="e.g., AWS Production Fleet"
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-ink-primary placeholder:text-ink-muted focus:border-link focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">Max Uses</label>
              <input
                name="maxUses"
                type="number"
                min="1"
                max="1000"
                defaultValue="10"
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-ink-primary focus:border-link focus:outline-none"
              />
              <p className="text-xs text-ink-muted mt-1">
                Number of sensors that can use this token
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">
                Expires In (days)
              </label>
              <input
                name="expiresIn"
                type="number"
                min="1"
                max="365"
                placeholder="Optional"
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-ink-primary placeholder:text-ink-muted focus:border-link focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">Region</label>
              <select
                name="region"
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-ink-primary focus:border-link focus:outline-none"
              >
                <option value="">Any Region</option>
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">EU (Ireland)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              </select>
            </div>
            <div className="flex gap-3 pt-4">
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="btn-ghost flex-1"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn-primary flex-1"
                disabled={generateMutation.isPending}
              >
                {generateMutation.isPending ? 'Creating...' : 'Create Token'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Generated Token Modal */}
      {generatedToken && (
        <Modal
          open
          onClose={() => {
            setGeneratedToken(null);
            setIsModalOpen(false);
          }}
          size="640px"
          title="Token Created"
        >
          <Stack direction="row" align="center" gap="smPlus" className="mb-4">
            <div className="w-10 h-10 bg-ac-green/10 flex items-center justify-center">
              <Check className="w-5 h-5 text-ac-green" />
            </div>
            <p className="text-sm text-ink-secondary">Copy this token now. It won't be shown again.</p>
          </Stack>
          <div className="bg-surface-subtle border border-border-subtle p-4 mb-4">
            <Stack direction="row" align="center" gap="sm">
              <code className="flex-1 text-sm font-mono text-ink-primary break-all">
                {generatedToken}
              </code>
              <Button
                onClick={handleCopyToken}
                variant="ghost"
                size="sm"
                icon={copiedToken ? <Check className="w-4 h-4 text-ac-green" /> : <Copy className="w-4 h-4" />}
                style={{ height: '32px', padding: 0 }}
                title="Copy token"
              />
            </Stack>
          </div>
          <div className="bg-ac-orange/10 border border-ac-orange/20 p-3 mb-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-ac-orange flex-shrink-0 mt-0.5" />
              <p className="text-sm text-ac-orange">
                This token grants sensor registration access. Store it securely and don't share it
                publicly.
              </p>
            </div>
          </div>
          <Button
            onClick={() => {
              setGeneratedToken(null);
              setIsModalOpen(false);
            }}
            fill
            size="sm"
          >
            Done
          </Button>
        </Modal>
      )}

      {/* Revoke Confirmation Modal */}
      {tokenToRevoke && (
        <Modal open onClose={() => setTokenToRevoke(null)} size="520px" title="Revoke Token">
          <Stack direction="row" align="center" gap="smPlus" className="mb-4">
            <div className="w-10 h-10 bg-ac-red/10 flex items-center justify-center">
              <Trash2 className="w-5 h-5 text-ac-red" />
            </div>
            <p className="text-sm text-ink-secondary">This action cannot be undone.</p>
          </Stack>
          <p className="text-sm text-ink-secondary mb-4">
            Sensors that haven't registered yet will no longer be able to use this token. Already
            registered sensors will not be affected.
          </p>
          <div className="flex gap-3">
            <Button onClick={() => setTokenToRevoke(null)} variant="ghost" size="sm" fill>
              Cancel
            </Button>
            <Button
              onClick={() => revokeMutation.mutate(tokenToRevoke)}
              size="sm"
              fill
              style={{ background: colors.red }}
              disabled={revokeMutation.isPending}
            >
              {revokeMutation.isPending ? 'Revoking...' : 'Revoke Token'}
            </Button>
          </div>
        </Modal>
      )}
    </div>
  );
}
