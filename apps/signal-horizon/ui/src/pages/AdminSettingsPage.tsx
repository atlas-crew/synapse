/**
 * Admin Settings Page
 *
 * Consolidated configuration panel for Signal Horizon Hub.
 * Includes tenant privacy settings, security policies, fleet-wide control,
 * and system information.
 */

import React, { useState, useRef } from 'react';
import {
  Shield,
  Share2,
  Server,
  Info,
  CheckCircle,
  AlertTriangle,
  Lock,
  Cpu,
  RefreshCw,
  Power,
  Key,
  Zap,
  Ban,
  Activity,
  Target,
  Network,
  Copy,
  X
} from 'lucide-react';
import { clsx } from 'clsx';
import { useTenantSettings, SharingPreference } from '../hooks/useTenantSettings';
import { usePolicies } from '../hooks/fleet/usePolicies';
import { useHubConfig, type HubConfig } from '../hooks/useHubConfig';
import { useFleetControl, useSensors, usePlaybooks, useBlocklist, useOnboarding } from '../hooks/fleet';
import { MetricCard } from '../components/fleet';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { useToast } from '../components/ui/Toast';
import { ToggleSwitch } from '../components/ui/ToggleSwitch';
import { ErrorBoundary } from '../components/ErrorBoundary';

const AdminSettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'tenant' | 'policies' | 'automation' | 'fleet' | 'synapse' | 'apparatus' | 'system'>('tenant');

  const {
    settings,
    isLoading: tenantLoading,
    updateSettings,
    isUpdating,
    requestWithdrawal,
    isWithdrawing
  } = useTenantSettings();

  const {
    policies,
    defaults,
    isLoading: policiesLoading
  } = usePolicies();

  const {
    config: hubConfig,
    isLoading: hubLoading,
    updateConfig,
    isUpdating: isUpdatingConfig
  } = useHubConfig();

  const {
    executeBatchControl,
    isExecutingBatch,
    revokeAllTokens,
    isRevokingAll
  } = useFleetControl();

  const { data: sensors = [] } = useSensors();
  const { playbooks, isLoading: playbooksLoading } = usePlaybooks();
  const { stats: blocklistStats, addBlock, isAddingBlock } = useBlocklist();
  const { stats: onboardingStats, createToken, isCreatingToken } = useOnboarding();

  // Toast & ConfirmDialog state
  const { toast, Toasts } = useToast();
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    description: string;
    variant: 'danger' | 'warning';
    onConfirm: () => void;
  } | null>(null);

  const showConfirm = (opts: { title: string; description: string; variant: 'danger' | 'warning'; onConfirm: () => void }) => {
    setConfirmDialog({ open: true, ...opts });
  };
  const closeConfirm = () => setConfirmDialog(null);

  // Inline form state for manual block
  const [blockIpInput, setBlockIpInput] = useState('');
  const [blockReasonInput, setBlockReasonInput] = useState('Manual admin block');
  const [showBlockForm, setShowBlockForm] = useState(false);

  // Inline form state for token creation
  const [tokenNameInput, setTokenNameInput] = useState('');
  const [showTokenForm, setShowTokenForm] = useState(false);
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  // Feature flags for Apparatus toggles
  const [featureFlags, setFeatureFlags] = useState({
    chaosEngine: false,
    movingTargetDefense: false,
    deceptiveEndpoints: true,
  });

  // Refs for form inputs (replacing document.getElementById)
  const portRef = useRef<HTMLInputElement>(null);
  const batchSizeRef = useRef<HTMLInputElement>(null);
  const batchTimeoutRef = useRef<HTMLInputElement>(null);
  const pushDelayRef = useRef<HTMLInputElement>(null);
  const cacheSizeRef = useRef<HTMLInputElement>(null);

  const handlePreferenceChange = async (pref: SharingPreference) => {
    const idempotencyKey = crypto.randomUUID();
    try {
      await updateSettings({ preference: pref, idempotencyKey });
    } catch (err) {
      console.error('Failed to update sharing preference:', err);
    }
  };

  const handleRevokeAll = () => {
    showConfirm({
      title: 'Revoke All Tokens',
      description: 'This will immediately invalidate ALL active sessions and API keys for your tenant. All sensors and users will be forced to re-authenticate. This action cannot be undone.',
      variant: 'danger',
      onConfirm: async () => {
        try {
          await revokeAllTokens();
          toast.success('All tokens successfully revoked. Epoch incremented.');
        } catch (err) {
          toast.error('Failed to revoke tokens: ' + (err instanceof Error ? err.message : 'Unknown error'));
        }
      },
    });
  };

  const handleWithdrawal = (type: 'CONTRIBUTION' | 'GDPR_ERASURE') => {
    const title = type === 'GDPR_ERASURE' ? 'Request Full Erasure' : 'Withdraw Contribution';
    const description = type === 'GDPR_ERASURE'
      ? 'This will delete ALL data associated with your tenant. This action is irreversible.'
      : 'This will withdraw all contributed signals from the global feed.';

    showConfirm({
      title,
      description,
      variant: type === 'GDPR_ERASURE' ? 'danger' : 'warning',
      onConfirm: async () => {
        try {
          await requestWithdrawal({ type });
          toast.success('Withdrawal request successfully submitted.');
        } catch (err) {
          toast.error('Failed to process withdrawal: ' + (err instanceof Error ? err.message : 'Unknown error'));
        }
      },
    });
  };

  const handleBatchAction = (command: 'reload' | 'drain') => {
    const sensorIds = sensors.map((s) => s.id);
    if (sensorIds.length === 0) {
      toast.info('No online sensors found to target.');
      return;
    }

    showConfirm({
      title: `Fleet ${command === 'reload' ? 'Reload' : 'Drain'}`,
      description: `Execute ${command} across ${sensorIds.length} sensors?`,
      variant: command === 'drain' ? 'danger' : 'warning',
      onConfirm: async () => {
        try {
          const result = await executeBatchControl({ command, sensorIds });
          toast.success(`${command} initiated: ${result.summary.success} succeeded, ${result.summary.failure} failed.`);
        } catch (err) {
          toast.error(`Failed to execute batch ${command}: ` + (err instanceof Error ? err.message : 'Unknown error'));
        }
      },
    });
  };

  const handleConfigUpdate = async (updates: Partial<HubConfig>) => {
    try {
      await updateConfig(updates);
    } catch (err) {
      console.error('Failed to update config:', err);
    }
  };

  const handleManualBlockSubmit = async () => {
    if (!blockIpInput.trim()) return;
    try {
      await addBlock({ ip: blockIpInput.trim(), reason: blockReasonInput.trim() || 'Manual admin block' });
      toast.success(`IP ${blockIpInput.trim()} successfully added to blocklist.`);
      setBlockIpInput('');
      setBlockReasonInput('Manual admin block');
      setShowBlockForm(false);
    } catch (err) {
      toast.error('Failed to add block: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  };

  const handleCreateTokenSubmit = async () => {
    if (!tokenNameInput.trim()) return;
    try {
      const result = await createToken(tokenNameInput.trim());
      setCreatedToken(result.token ?? null);
      setTokenNameInput('');
      setShowTokenForm(false);
      toast.success('Registration token created successfully.');
    } catch (err) {
      toast.error('Failed to create token: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success('Token copied to clipboard.');
    } catch {
      toast.error('Failed to copy to clipboard.');
    }
  };

  const tabs = [
    { id: 'tenant', label: 'Tenant & Privacy', icon: Shield },
    { id: 'policies', label: 'Security Policies', icon: Lock },
    { id: 'automation', label: 'Automation & Rules', icon: Zap },
    { id: 'fleet', label: 'Fleet Control', icon: Server },
    { id: 'synapse', label: 'Synapse-Pingora', icon: Network },
    { id: 'apparatus', label: 'Apparatus', icon: Target },
    { id: 'system', label: 'System & Environment', icon: Info },
  ] as const;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8 font-sans">
      <header className="flex justify-between items-end border-b border-border-subtle pb-6">
        <div>
          <h1 className="text-3xl font-light text-ink-primary mb-2 uppercase tracking-tight">Admin Settings</h1>
          <p className="text-ink-secondary">Global configuration and fleet management for Signal Horizon.</p>
        </div>
        <div className="flex gap-4">
          <div className="flex gap-2 text-xs font-mono">
            <span className="bg-surface-subtle px-3 py-1 text-ink-primary border border-border-subtle">MODE: HUB_ADMIN</span>
          </div>
        </div>
      </header>

      <div className="flex flex-col lg:flex-row gap-8">
        {/* Sidebar Navigation */}
        <aside className="w-full lg:w-64 flex-shrink-0">
          <nav className="flex flex-col space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'flex items-center gap-3 px-4 py-3 text-sm font-medium transition-all border-l-4',
                  'focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1',
                  activeTab === tab.id
                    ? 'bg-ac-navy text-white border-ac-magenta'
                    : 'bg-surface-subtle text-ink-primary border-transparent hover:bg-border-subtle'
                )}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="mt-10 p-4 bg-ac-card-dark text-white space-y-4">
            <div className="flex items-center gap-2 text-ac-sky-blue">
              <Key className="w-4 h-4" />
              <span className="text-xs font-bold uppercase tracking-widest">Quick Access</span>
            </div>
            <a href="/fleet/keys" className="block text-xs hover:text-ac-sky-blue transition-colors">Manage Sensor API Keys</a>
            <a href="/fleet/connectivity" className="block text-xs hover:text-ac-sky-blue transition-colors">Network Diagnostics</a>
          </div>
        </aside>

        {/* Tab Content */}
        <main className="flex-1 min-w-0">
          {activeTab === 'tenant' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card space-y-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Collective Defense & Privacy</h2>
                  <Share2 className="w-5 h-5 text-ac-blue" />
                </div>

                <p className="text-sm text-ink-secondary leading-relaxed">
                  Signal Horizon utilizes Collective Defense to share threat intelligence across the fleet.
                  Choose how your tenant contributes to and receives updates from the global threat feed.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                  {[
                    { id: 'CONTRIBUTE_AND_RECEIVE', label: 'Full Participation', desc: 'Share anonymous signals and receive real-time blocklists.' },
                    { id: 'RECEIVE_ONLY', label: 'Receiver Only', desc: 'Get global threat updates without sharing any signals.' },
                    { id: 'CONTRIBUTE_ONLY', label: 'Contributor Only', desc: 'Share threat data without receiving global updates.' },
                    { id: 'ISOLATED', label: 'Isolated Mode', desc: 'No data sharing. Local intelligence only.' },
                  ].map((pref) => (
                    <button
                      key={pref.id}
                      onClick={() => handlePreferenceChange(pref.id as SharingPreference)}
                      disabled={isUpdating || tenantLoading}
                      className={clsx(
                        'p-4 text-left border-2 transition-all group',
                        'focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1',
                        settings?.data.sharingPreference === pref.id
                          ? 'border-ac-blue bg-surface-subtle'
                          : 'border-border-subtle hover:border-ac-blue/50 hover:bg-surface-subtle/50'
                      )}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-sm text-ink-primary">{pref.label}</span>
                        {settings?.data.sharingPreference === pref.id && (
                          <CheckCircle className="w-4 h-4 text-status-success" />
                        )}
                      </div>
                      <p className="text-xs text-ink-muted group-hover:text-ink-secondary transition-colors">{pref.desc}</p>
                    </button>
                  ))}
                </div>

                <div className="mt-8 p-4 bg-surface-subtle flex items-start gap-4">
                  <AlertTriangle className="w-5 h-5 text-ac-orange flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <p className="text-xs font-bold text-ink-primary">Legal & Compliance Notice</p>
                    <p className="text-xs text-ink-secondary">
                      Changing your sharing preference may trigger a data withdrawal process.
                      Signals previously shared under 'Full Participation' will be scrubbed if moving to 'Isolated'.
                    </p>
                  </div>
                </div>
              </section>

              <section className="bg-surface-card border-t-4 border-status-error p-8 shadow-card space-y-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Security Panic Button</h2>
                  <Lock className="w-5 h-5 text-status-error" />
                </div>

                <p className="text-sm text-ink-secondary leading-relaxed">
                  In the event of a suspected account compromise or global security incident, you can invalidate all active sessions for your tenant.
                </p>

                <div className="p-6 border border-status-error/20 bg-status-error/5 space-y-4">
                  <div className="flex items-center gap-3 text-status-error">
                    <RefreshCw className="w-5 h-5 animate-spin-slow" />
                    <h3 className="font-bold text-sm uppercase tracking-wider">Invalidate All Sessions</h3>
                  </div>
                  <p className="text-xs text-ink-muted">
                    This will increment the security epoch for your tenant. All existing JWTs and session tokens will be immediately invalidated.
                    Users and sensors will be required to re-authenticate.
                  </p>
                  <button
                    onClick={handleRevokeAll}
                    disabled={isRevokingAll}
                    className="px-6 h-12 bg-status-error text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-magenta-dark disabled:opacity-50 transition-colors shadow-lg shadow-status-error/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                  >
                    {isRevokingAll ? 'Revoking...' : 'Revoke All Tokens'}
                  </button>
                </div>
              </section>

              <section className="bg-surface-card border-t-4 border-border-subtle p-8 shadow-card space-y-6">
                <h3 className="text-lg font-light text-ink-primary uppercase tracking-tight">Data Consent Status</h3>
                <div className="flex items-center gap-4 p-4 border border-border-subtle bg-surface-subtle">
                  {settings?.metadata.consent.status === 'acknowledged' ? (
                    <>
                      <div className="w-10 h-10 bg-status-success/10 flex items-center justify-center text-status-success">
                        <CheckCircle className="w-6 h-6" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-ink-primary">Consent Acknowledged</p>
                        <p className="text-xs text-ink-muted">
                          Last granted: {settings.metadata.consent.acknowledgedAt ? new Date(settings.metadata.consent.acknowledgedAt).toLocaleString() : 'N/A'}
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="w-10 h-10 bg-ac-orange/10 flex items-center justify-center text-ac-orange">
                        <AlertTriangle className="w-6 h-6" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-ink-primary">Consent Required</p>
                        <p className="text-xs text-ink-muted">Please review and accept the global data sharing policy.</p>
                      </div>
                      <button className="ml-auto px-4 py-2 bg-ac-blue text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-dark transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1">
                        Review Policy
                      </button>
                    </>
                  )}
                </div>
              </section>

              <section className="bg-surface-card border-t-4 border-ink-muted p-8 shadow-card space-y-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Data Sovereignty</h2>
                  <Shield className="w-5 h-5 text-ink-muted" />
                </div>
                <p className="text-sm text-ink-secondary">
                  Retroactively withdraw contributed signals or exercise GDPR Right to Erasure for all tenant telemetry.
                </p>
                <div className="flex gap-4">
                  <button
                    onClick={() => handleWithdrawal('CONTRIBUTION')}
                    disabled={isWithdrawing}
                    className="flex-1 h-12 border-2 border-border-subtle text-ink-primary text-xs font-bold uppercase tracking-widest hover:bg-surface-subtle disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                  >
                    Withdraw Contribution
                  </button>
                  <button
                    onClick={() => handleWithdrawal('GDPR_ERASURE')}
                    disabled={isWithdrawing}
                    className="flex-1 h-12 border-2 border-status-error text-status-error text-xs font-bold uppercase tracking-widest hover:bg-status-error/5 disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                  >
                    Request Full Erasure
                  </button>
                </div>
              </section>
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'policies' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card">
                <div className="flex justify-between items-center mb-8">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Security Policy Templates</h2>
                  <button className="px-4 py-2 bg-ac-blue text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-dark transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1">
                    New Template
                  </button>
                </div>

                <div className="space-y-4">
                  {policiesLoading ? (
                    <div className="py-12 text-center text-ink-muted">Loading policies...</div>
                  ) : policies.length === 0 ? (
                    <div className="py-12 text-center text-ink-muted">No custom policies defined. Defaults are in use.</div>
                  ) : (
                    policies.map((policy) => (
                      <div key={policy.id} className="group flex items-center justify-between p-5 bg-surface-subtle hover:bg-ac-navy hover:text-white transition-all border-l-4 border-ac-sky-blue">
                        <div>
                          <div className="flex items-center gap-3 mb-1">
                            <span className="font-bold text-sm">{policy.name}</span>
                            <span className={clsx(
                              'text-xs px-2 py-0.5 border uppercase font-mono font-bold',
                              policy.severity === 'strict' ? 'border-status-error text-status-error group-hover:bg-status-error group-hover:text-white' :
                              policy.severity === 'standard' ? 'border-ac-blue text-ac-blue group-hover:bg-ac-blue group-hover:text-white' :
                              'border-ink-muted text-ink-muted group-hover:bg-ink-muted group-hover:text-white'
                            )}>
                              {policy.severity}
                            </span>
                            {policy.isDefault && <span className="text-xs text-status-success font-bold uppercase tracking-tighter group-hover:text-white">DEFAULT</span>}
                          </div>
                          <p className="text-xs text-ink-muted group-hover:text-white/60">{policy.description || 'No description provided.'}</p>
                        </div>
                        <div className="text-right flex items-center gap-4">
                          <div className="text-xs opacity-60">VER {policy.version}.0</div>
                          <button className="text-xs font-bold text-ac-blue group-hover:text-ac-sky-blue uppercase tracking-widest focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1">Edit</button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <MetricCard label="Active Templates" value={policies.length} />
                <MetricCard label="Default Templates" value={defaults.length} />
                <MetricCard label="Revision Level" value="v3.2" />
              </div>
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'automation' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card">
                <div className="flex justify-between items-center mb-8">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Active Blocklist</h2>
                  <button
                    onClick={() => setShowBlockForm(true)}
                    disabled={isAddingBlock || showBlockForm}
                    className="px-4 py-2 bg-status-error text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-magenta-dark disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                  >
                    {isAddingBlock ? 'Adding...' : 'Add Manual Block'}
                  </button>
                </div>

                {showBlockForm && (
                  <div className="mb-6 p-4 border border-border-subtle bg-surface-subtle space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-ink-primary uppercase tracking-wider">Add Manual Block</h4>
                      <button
                        onClick={() => { setShowBlockForm(false); setBlockIpInput(''); setBlockReasonInput('Manual admin block'); }}
                        className="text-ink-muted hover:text-ink-primary transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        aria-label="Close block form"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1">
                        <label htmlFor="block-ip" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">IP Address</label>
                        <input
                          id="block-ip"
                          type="text"
                          value={blockIpInput}
                          onChange={(e) => setBlockIpInput(e.target.value)}
                          placeholder="e.g. 192.168.1.100"
                          className="w-full bg-surface-card border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        />
                      </div>
                      <div className="space-y-1">
                        <label htmlFor="block-reason" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Reason</label>
                        <input
                          id="block-reason"
                          type="text"
                          value={blockReasonInput}
                          onChange={(e) => setBlockReasonInput(e.target.value)}
                          className="w-full bg-surface-card border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        />
                      </div>
                    </div>
                    <div className="flex justify-end gap-3">
                      <button
                        onClick={() => { setShowBlockForm(false); setBlockIpInput(''); setBlockReasonInput('Manual admin block'); }}
                        className="px-4 py-2 border border-border-subtle text-ink-secondary text-xs font-bold uppercase tracking-widest hover:bg-surface-subtle transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleManualBlockSubmit}
                        disabled={isAddingBlock || !blockIpInput.trim()}
                        className="px-4 py-2 bg-status-error text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-magenta-dark disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                      >
                        {isAddingBlock ? 'Adding...' : 'Block IP'}
                      </button>
                    </div>
                  </div>
                )}

                <div className="bg-surface-subtle p-4 border border-border-subtle flex items-center justify-between mb-6">
                  <div className="flex items-center gap-4">
                    <Ban className="w-5 h-5 text-status-error" />
                    <div>
                      <p className="text-sm font-bold text-ink-primary">Dynamic IP Blocking</p>
                      <p className="text-xs text-ink-muted">Fleet-wide blocks are automatically propagated to all sensors within 50ms.</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-light text-ink-primary">{blocklistStats.totalActive.toLocaleString()}</p>
                    <p className="text-xs font-bold text-ink-muted uppercase tracking-tighter">Active Indicators</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-bold text-ink-primary uppercase tracking-widest mb-4">Automation Playbooks</h3>
                  {playbooksLoading ? (
                    <div className="py-8 text-center text-ink-muted text-xs">Loading playbooks...</div>
                  ) : playbooks.length === 0 ? (
                    <div className="py-8 text-center text-ink-muted text-xs">No active playbooks defined.</div>
                  ) : (
                    playbooks.map((pb) => (
                      <div key={pb.id} className="p-4 border border-border-subtle flex items-center justify-between hover:bg-surface-subtle transition-colors group cursor-pointer">
                        <div className="flex items-center gap-4">
                          <Zap className={clsx("w-4 h-4", pb.isActive ? "text-status-success" : "text-ink-muted")} />
                          <div>
                            <p className="text-sm font-bold text-ink-primary">{pb.name}</p>
                            <p className="text-xs font-mono text-ink-muted">
                              {pb.triggerType === 'MANUAL' ? 'Manual Trigger' : `IF ${pb.triggerType} ${pb.triggerValue ? `== ${pb.triggerValue}` : ''}`}
                            </p>
                          </div>
                        </div>
                        <CheckCircle className="w-4 h-4 text-status-success opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    ))
                  )}
                </div>
              </section>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <MetricCard label="Manual Blocks" value={blocklistStats.manualCount} />
                <MetricCard label="Auto Blocks (24h)" value={blocklistStats.autoCount24h} />
                <MetricCard label="Sync Rate" value={`${blocklistStats.syncRate}%`} />
              </div>
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'fleet' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card">
                <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight mb-6">Fleet-Wide Actions</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="p-6 border border-border-subtle space-y-4">
                    <div className="flex items-center gap-3 text-ac-blue">
                      <RefreshCw className="w-5 h-5" />
                      <h3 className="font-bold text-sm uppercase tracking-wider">Hot Reload</h3>
                    </div>
                    <p className="text-xs text-ink-muted leading-relaxed">
                      Triggers a configuration reload across all online sensors. No service interruption or connection draining required.
                    </p>
                    <button
                      onClick={() => handleBatchAction('reload')}
                      disabled={isExecutingBatch}
                      className="w-full h-12 bg-ac-navy text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-darker disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                    >
                      {isExecutingBatch ? 'Executing...' : 'Execute Batch Reload'}
                    </button>
                  </div>

                  <div className="p-6 border border-border-subtle space-y-4">
                    <div className="flex items-center gap-3 text-status-error">
                      <Power className="w-5 h-5" />
                      <h3 className="font-bold text-sm uppercase tracking-wider">Fleet Drain</h3>
                    </div>
                    <p className="text-xs text-ink-muted leading-relaxed">
                      Commands all sensors to stop accepting new connections and gracefully finish existing ones. Use for maintenance.
                    </p>
                    <button
                      onClick={() => handleBatchAction('drain')}
                      disabled={isExecutingBatch}
                      className="w-full h-12 border-2 border-status-error text-status-error text-xs font-bold uppercase tracking-widest hover:bg-status-error hover:text-white disabled:opacity-50 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                    >
                      {isExecutingBatch ? 'Executing...' : 'Initiate Fleet Drain'}
                    </button>
                  </div>
                </div>
              </section>

              <section className="bg-surface-card border-t-4 border-status-success p-8 shadow-card">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Provisioning & Onboarding</h2>
                  <button
                    onClick={() => setShowTokenForm(true)}
                    disabled={isCreatingToken || showTokenForm}
                    className="px-4 py-2 bg-status-success text-white text-xs font-bold uppercase tracking-widest hover:bg-status-success/80 disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                  >
                    {isCreatingToken ? 'Generating...' : 'New Registration Token'}
                  </button>
                </div>

                {showTokenForm && (
                  <div className="mb-6 p-4 border border-border-subtle bg-surface-subtle space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-ink-primary uppercase tracking-wider">Create Registration Token</h4>
                      <button
                        onClick={() => { setShowTokenForm(false); setTokenNameInput(''); }}
                        className="text-ink-muted hover:text-ink-primary transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        aria-label="Close token form"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="space-y-1">
                      <label htmlFor="token-name" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Token Name</label>
                      <input
                        id="token-name"
                        type="text"
                        value={tokenNameInput}
                        onChange={(e) => setTokenNameInput(e.target.value)}
                        placeholder='e.g. "West Coast Fleet"'
                        className="w-full bg-surface-card border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                      />
                    </div>
                    <div className="flex justify-end gap-3">
                      <button
                        onClick={() => { setShowTokenForm(false); setTokenNameInput(''); }}
                        className="px-4 py-2 border border-border-subtle text-ink-secondary text-xs font-bold uppercase tracking-widest hover:bg-surface-subtle transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleCreateTokenSubmit}
                        disabled={isCreatingToken || !tokenNameInput.trim()}
                        className="px-4 py-2 bg-status-success text-white text-xs font-bold uppercase tracking-widest hover:bg-status-success/80 disabled:opacity-50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                      >
                        {isCreatingToken ? 'Generating...' : 'Create Token'}
                      </button>
                    </div>
                  </div>
                )}

                {createdToken && (
                  <div className="mb-6 p-4 border border-status-success bg-status-success/10 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-ink-primary uppercase tracking-wider">Token Created</h4>
                      <button
                        onClick={() => setCreatedToken(null)}
                        className="text-ink-muted hover:text-ink-primary transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        aria-label="Dismiss token display"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 bg-surface-card border border-border-subtle p-3 text-xs font-mono text-ink-primary break-all">{createdToken}</code>
                      <button
                        onClick={() => copyToClipboard(createdToken)}
                        className="flex-shrink-0 p-3 border border-border-subtle bg-surface-card hover:bg-surface-subtle transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        aria-label="Copy token to clipboard"
                      >
                        <Copy className="w-4 h-4 text-ink-secondary" />
                      </button>
                    </div>
                    <p className="text-xs font-bold text-status-error">
                      <AlertTriangle className="w-3 h-3 inline mr-1" />
                      SAVE THIS SECURELY. It will not be shown again.
                    </p>
                  </div>
                )}

                <div className="p-4 border border-border-subtle bg-surface-subtle flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-ink-primary">Zero-Touch Registration</p>
                    <p className="text-xs text-ink-muted">
                      {onboardingStats.activeTokens} Active tokens available. {onboardingStats.pendingApprovals} sensors awaiting manual approval.
                    </p>
                  </div>
                  <a href="/fleet/onboarding" className="text-xs font-bold text-ac-blue hover:underline uppercase tracking-widest">Open Onboarding -&gt;</a>
                </div>
              </section>

              {(() => {
                const totalSensors = sensors.length;
                const connectedSensors = sensors.filter((s) => s.status === 'online').length;
                const convergence = totalSensors > 0 ? (connectedSensors / totalSensors) * 100 : 0;
                const fleetState = convergence > 90 ? 'STEADY' : convergence > 50 ? 'DEGRADED' : 'CRITICAL';

                // Fleet status summary
                const lastSyncText = totalSensors > 0 ? 'Live' : 'Never';

                return (
                  <div className="bg-ac-card-dark p-8 text-white relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-2 text-[8px] font-mono text-white/20 uppercase">FLEET_ADVISORY_01</div>
                    <h3 className="text-lg font-light mb-4 uppercase tracking-wider text-ac-sky-blue">Strategic Fleet Status</h3>
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
                      <div>
                        <div className="text-xs font-bold text-white/40 uppercase tracking-widest mb-1">Convergence</div>
                        <div className="text-2xl font-light">{convergence.toFixed(1)}%</div>
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white/40 uppercase tracking-widest mb-1">Drift Threshold</div>
                        <div className="text-2xl font-light text-status-success">NOMINAL</div>
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white/40 uppercase tracking-widest mb-1">Last Sync</div>
                        <div className="text-2xl font-light">{lastSyncText}</div>
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white/40 uppercase tracking-widest mb-1">Fleet State</div>
                        <div className={clsx("text-2xl font-light", fleetState === 'STEADY' ? "text-status-success" : "text-ac-orange")}>
                          {fleetState}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'synapse' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card space-y-6">
                <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Synapse-Pingora Connectivity</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-2">
                    <label htmlFor="synapse-risk-server" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Risk Server (Proxy)</label>
                    <input id="synapse-risk-server" type="text" className="w-full bg-surface-subtle border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue="http://localhost:3000" />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="synapse-admin-url" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Synapse Admin URL</label>
                    <input id="synapse-admin-url" type="text" className="w-full bg-surface-subtle border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue="http://localhost:8080" />
                  </div>
                </div>
                <div className="flex items-center gap-4 p-4 border border-ac-blue/20 bg-ac-blue/5">
                  <Activity className="w-5 h-5 text-ac-blue" />
                  <p className="text-xs text-ink-secondary">When **Synapse Admin URL** is configured, the Hub will bypass the Risk Server for direct sensor introspection.</p>
                </div>
              </section>

              <section className="bg-surface-card border-t-4 border-ac-magenta p-8 shadow-card space-y-6">
                <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Fleet Tunneling</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  <div className="p-4 bg-surface-subtle border border-border-subtle space-y-3">
                    <p className="text-xs font-bold text-ink-primary uppercase tracking-widest">Tunnel Ports</p>
                    <div className="flex gap-2">
                      <span className="bg-ac-navy text-white px-2 py-1 text-xs font-mono">3100 (WS)</span>
                      <span className="bg-ac-navy text-white px-2 py-1 text-xs font-mono">8080 (Admin)</span>
                    </div>
                  </div>
                  <div className="p-4 bg-surface-subtle border border-border-subtle space-y-3">
                    <p className="text-xs font-bold text-ink-primary uppercase tracking-widest">Active Tunnels</p>
                    <p className="text-lg font-light text-ink-primary">12 / 15</p>
                  </div>
                  <div className="p-4 bg-surface-subtle border border-border-subtle space-y-3">
                    <p className="text-xs font-bold text-ink-primary uppercase tracking-widest">Encryption</p>
                    <span className="bg-status-success text-white px-2 py-1 text-xs font-bold uppercase">mTLS Active</span>
                  </div>
                </div>
                <button className="h-12 px-6 bg-ac-navy text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-darker transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1">
                  Update Tunnel Configuration
                </button>
              </section>
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'apparatus' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Red Team Panel */}
                <section className="bg-surface-card border-t-4 border-status-error p-8 shadow-card space-y-6">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Red-Team Simulation</h2>
                    <Target className="w-5 h-5 text-status-error" />
                  </div>
                  <p className="text-xs text-ink-muted">Coordinate with the Apparatus cluster to generate controlled attack simulations for testing and training.</p>

                  <div className="space-y-4">
                    <div className="p-4 border border-border-subtle hover:border-status-error/50 transition-colors group cursor-pointer">
                      <p className="text-sm font-bold text-ink-primary">Infrastructure Probing</p>
                      <p className="text-xs text-ink-muted">Simulate mass scanning and fingerprinting against edge nodes.</p>
                    </div>
                    <div className="p-4 border border-border-subtle hover:border-status-error/50 transition-colors group cursor-pointer">
                      <p className="text-sm font-bold text-ink-primary">Auth Burst Attack</p>
                      <p className="text-xs text-ink-muted">Coordinate a distributed credential stuffing simulation.</p>
                    </div>
                  </div>

                  <button className="w-full h-12 border-2 border-status-error text-status-error text-xs font-bold uppercase tracking-widest hover:bg-status-error hover:text-white transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1">
                    Initiate Apparatus Sync
                  </button>
                </section>

                {/* Active Defense Panel */}
                <section className="bg-surface-card border-t-4 border-status-success p-8 shadow-card space-y-6">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight">Active Defense (Apparatus)</h2>
                    <Zap className="w-5 h-5 text-status-success" />
                  </div>
                  <p className="text-xs text-ink-muted">Advanced deception and resilience controls managed via Apparatus integration.</p>

                  <div className="space-y-6">
                    <div className="flex items-center justify-between py-2 border-b border-border-subtle">
                      <div>
                        <p className="text-sm font-bold text-ink-primary">Chaos Engine</p>
                        <p className="text-xs text-ink-muted">Randomized delay and error injection.</p>
                      </div>
                      <ToggleSwitch
                        checked={featureFlags.chaosEngine}
                        onChange={(checked) => setFeatureFlags((prev) => ({ ...prev, chaosEngine: checked }))}
                        label="Toggle Chaos Engine"
                        size="sm"
                      />
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-border-subtle">
                      <div>
                        <p className="text-sm font-bold text-ink-primary">Moving Target Defense</p>
                        <p className="text-xs text-ink-muted">Dynamic upstream address rotation.</p>
                      </div>
                      <ToggleSwitch
                        checked={featureFlags.movingTargetDefense}
                        onChange={(checked) => setFeatureFlags((prev) => ({ ...prev, movingTargetDefense: checked }))}
                        label="Toggle Moving Target Defense"
                        size="sm"
                      />
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-border-subtle">
                      <div>
                        <p className="text-sm font-bold text-ink-primary">Deceptive Endpoints</p>
                        <p className="text-xs text-ink-muted">Deploy honeypot URLs across the fleet.</p>
                      </div>
                      <ToggleSwitch
                        checked={featureFlags.deceptiveEndpoints}
                        onChange={(checked) => setFeatureFlags((prev) => ({ ...prev, deceptiveEndpoints: checked }))}
                        label="Toggle Deceptive Endpoints"
                        size="sm"
                      />
                    </div>
                  </div>
                </section>
              </div>

              <section className="bg-ac-card-dark p-8 text-white space-y-6">
                <h3 className="text-lg font-light uppercase tracking-wider text-ac-sky-blue">Apparatus Connection</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-white/40 uppercase tracking-widest">Cluster Host</label>
                    <div className="text-sm font-mono text-ac-sky-blue">apparatus.internal.svc</div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-white/40 uppercase tracking-widest">Command Port</label>
                    <div className="text-sm font-mono text-ac-sky-blue">4000</div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-white/40 uppercase tracking-widest">API Secret</label>
                    <div className="text-sm font-mono text-ac-sky-blue">••••••••••••••••</div>
                  </div>
                </div>
              </section>
            </div>
            </ErrorBoundary>
          )}

          {activeTab === 'system' && (
            <ErrorBoundary>
            <div className="space-y-8 animate-in fade-in duration-300">
              <section className="bg-surface-card border-t-4 border-ac-blue p-8 shadow-card">
                <h2 className="text-xl font-light text-ink-primary uppercase tracking-tight mb-8">Hub Runtime Configuration</h2>

                {hubLoading ? (
                  <div className="py-12 text-center text-ink-muted">Loading hub configuration...</div>
                ) : (
                  <div className="space-y-8">
                    {/* Server Settings */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      <div className="space-y-2">
                        <label htmlFor="system-host" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">API Host</label>
                        <input
                          id="system-host"
                          type="text"
                          className="w-full bg-surface-subtle border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                          defaultValue={hubConfig?.server.host || '0.0.0.0'}
                        />
                      </div>
                      <div className="space-y-2">
                        <label htmlFor="system-port" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">API Port (Requires Restart)</label>
                        <div className="flex gap-2">
                          <input
                            type="number"
                            id="system-port"
                            ref={portRef}
                            className="flex-1 bg-surface-subtle border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                            defaultValue={hubConfig?.server.port || 3100}
                          />
                          <button
                            onClick={() => {
                              const port = parseInt(portRef.current?.value || '3100');
                              showConfirm({
                                title: 'Change API Port',
                                description: `Changing the port to ${port} will require a manual restart of the Signal Horizon service. Proceed?`,
                                variant: 'warning',
                                onConfirm: () => {
                                  handleConfigUpdate({ server: { port } } as Partial<HubConfig>);
                                },
                              });
                            }}
                            disabled={isUpdatingConfig}
                            className="px-4 bg-ac-blue text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-dark disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                          >
                            Apply
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      <div className="space-y-2">
                        <label className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Database URL</label>
                        <div className="bg-surface-subtle border border-border-subtle p-3 text-sm font-mono text-ink-muted truncate">
                          {hubConfig?.database.url || 'postgres://****:****@localhost:5432/signal_horizon'}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <label htmlFor="system-log-level" className="text-xs font-bold text-ink-primary uppercase tracking-widest block">Log Level</label>
                        <select
                          id="system-log-level"
                          className="w-full bg-surface-subtle border border-border-subtle p-3 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                          defaultValue={hubConfig?.logging.level}
                          onChange={(e) => handleConfigUpdate({ logging: { level: e.target.value } } as Partial<HubConfig>)}
                          disabled={isUpdatingConfig}
                        >
                          {['trace', 'debug', 'info', 'warn', 'error', 'fatal'].map(level => (
                            <option key={level} value={level}>{level.toUpperCase()}</option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {/* Feature Flags */}
                    <div className="pt-8 border-t border-border-subtle space-y-6">
                      <h3 className="text-sm font-bold text-ink-primary uppercase tracking-widest mb-4">Feature Flags</h3>

                      <div className="flex items-center justify-between py-4 border-b border-border-subtle">
                        <div>
                          <div className="flex items-center gap-2 font-bold text-sm text-ink-primary">
                            <Cpu className="w-4 h-4" /> Chaos Engine
                          </div>
                          <p className="text-xs text-ink-muted">Enable randomized traffic injection for resilience testing.</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-ink-muted uppercase tracking-tighter">
                            {hubConfig?.fleetCommands?.enableToggleChaos ? 'ENABLED' : 'DISABLED'}
                          </span>
                          <ToggleSwitch
                            checked={!!hubConfig?.fleetCommands?.enableToggleChaos}
                            onChange={(checked) => handleConfigUpdate({
                              fleetCommands: { enableToggleChaos: checked },
                            } as Partial<HubConfig>)}
                            disabled={isUpdatingConfig || hubLoading}
                            label="Toggle Chaos Engine"
                          />
                        </div>
                      </div>

                      <div className="flex items-center justify-between py-4 border-b border-border-subtle">
                        <div>
                          <div className="flex items-center gap-2 font-bold text-sm text-ink-primary">
                            <Shield className="w-4 h-4" /> Moving Target Defense
                          </div>
                          <p className="text-xs text-ink-muted">Rotate upstream addresses dynamically to frustrate reconnaissance.</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-ink-muted uppercase tracking-tighter">
                            {hubConfig?.fleetCommands?.enableToggleMtd ? 'ENABLED' : 'DISABLED'}
                          </span>
                          <ToggleSwitch
                            checked={!!hubConfig?.fleetCommands?.enableToggleMtd}
                            onChange={(checked) => handleConfigUpdate({
                              fleetCommands: { enableToggleMtd: checked },
                            } as Partial<HubConfig>)}
                            disabled={isUpdatingConfig || hubLoading}
                            label="Toggle Moving Target Defense"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Batching & Performance */}
                    <div className="pt-8 border-t border-border-subtle">
                      <h3 className="text-sm font-bold text-ink-primary uppercase tracking-widest mb-6">Performance Tuning</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        <div className="space-y-1">
                          <label htmlFor="tuning-batchSize" className="text-xs font-bold text-ink-muted uppercase tracking-tighter block">Signal Batch Size</label>
                          <input type="number" id="tuning-batchSize" ref={batchSizeRef} className="w-full bg-surface-subtle border border-border-subtle p-2 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue={hubConfig?.aggregator.batchSize || 100} />
                        </div>
                        <div className="space-y-1">
                          <label htmlFor="tuning-batchTimeoutMs" className="text-xs font-bold text-ink-muted uppercase tracking-tighter block">Batch Timeout (ms)</label>
                          <input type="number" id="tuning-batchTimeoutMs" ref={batchTimeoutRef} className="w-full bg-surface-subtle border border-border-subtle p-2 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue={hubConfig?.aggregator.batchTimeoutMs || 5000} />
                        </div>
                        <div className="space-y-1">
                          <label htmlFor="tuning-pushDelayMs" className="text-xs font-bold text-ink-muted uppercase tracking-tighter block">Blocklist Delay (ms)</label>
                          <input type="number" id="tuning-pushDelayMs" ref={pushDelayRef} className="w-full bg-surface-subtle border border-border-subtle p-2 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue={hubConfig?.broadcaster.pushDelayMs || 50} />
                        </div>
                        <div className="space-y-1">
                          <label htmlFor="tuning-cacheSize" className="text-xs font-bold text-ink-muted uppercase tracking-tighter block">Cache Limit</label>
                          <input type="number" id="tuning-cacheSize" ref={cacheSizeRef} className="w-full bg-surface-subtle border border-border-subtle p-2 text-sm font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1" defaultValue={hubConfig?.broadcaster.cacheSize || 100000} />
                        </div>
                      </div>
                      <div className="mt-6 flex justify-end">
                        <button
                          onClick={() => {
                            const batchSize = parseInt(batchSizeRef.current?.value || '100');
                            const batchTimeoutMs = parseInt(batchTimeoutRef.current?.value || '5000');
                            const pushDelayMs = parseInt(pushDelayRef.current?.value || '50');
                            const cacheSize = parseInt(cacheSizeRef.current?.value || '100000');
                            handleConfigUpdate({
                              aggregator: { batchSize, batchTimeoutMs },
                              broadcaster: { pushDelayMs, cacheSize }
                            } as Partial<HubConfig>);
                          }}
                          disabled={isUpdatingConfig}
                          className="h-10 px-6 bg-ac-navy text-white text-xs font-bold uppercase tracking-widest hover:bg-ac-blue-darker disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-offset-1"
                        >
                          {isUpdatingConfig ? 'Saving...' : 'Save Tuning Parameters'}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </section>

              <div className="p-6 border-l-4 border-ac-magenta bg-surface-subtle space-y-2">
                <h4 className="text-xs font-bold text-ink-primary uppercase tracking-widest">Environment Context</h4>
                <div className="flex items-center justify-between text-xs font-mono text-ink-muted">
                  <span>NODE_ENV: {hubConfig?.env || 'development'}</span>
                  <span>BUILD_TAG: 2026.02.06-stable</span>
                  <span>UI_PORT: 5180</span>
                </div>
              </div>
            </div>
            </ErrorBoundary>
          )}
        </main>
      </div>

      {confirmDialog && (
        <ConfirmDialog
          open={confirmDialog.open}
          title={confirmDialog.title}
          description={confirmDialog.description}
          variant={confirmDialog.variant}
          onConfirm={() => { confirmDialog.onConfirm(); closeConfirm(); }}
          onCancel={closeConfirm}
        />
      )}
      {Toasts}
    </div>
  );
};

export default AdminSettingsPage;
