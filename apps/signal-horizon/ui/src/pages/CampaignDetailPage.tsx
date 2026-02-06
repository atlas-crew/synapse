/**
 * Campaign Detail Page
 * Timeline, participating actors, correlation signals, actions
 */

import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { TOOLTIP_CONTENT_STYLE, TOOLTIP_LABEL_STYLE, TOOLTIP_ITEM_STYLE } from '../lib/chartTheme';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { Breadcrumb } from '../components/ui/Breadcrumb';
import {
  Target,
  Clock,
  Users,
  Shield,
  Activity,
  ExternalLink,
  Flame,
  Swords,
  ChevronRight,
} from 'lucide-react';
import { CampaignGraph } from '../components/soc/CampaignGraph';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { clsx } from 'clsx';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { useHorizonStore } from '../stores/horizonStore';

const mockCorrelationSignals = [
  { name: 'HTTP Fingerprint Match', confidence: 0.98, color: 'bg-ac-green' },
  { name: 'TLS Fingerprint Match', confidence: 0.95, color: 'bg-ac-blue' },
  { name: 'Timing Correlation', confidence: 0.89, color: 'bg-ac-orange' },
  { name: 'Target Endpoint Match', confidence: 0.82, color: 'bg-ac-purple' },
  { name: 'Network Proximity', confidence: 0.72, color: 'bg-ac-red' },
];

const attackTimeline = [
  { time: '10:15', volume: 120 },
  { time: '10:30', volume: 240 },
  { time: '10:45', volume: 420 },
  { time: '11:00', volume: 820 },
  { time: '11:15', volume: 1340 },
  { time: '11:30', volume: 2100 },
  { time: '11:45', volume: 1500 },
  { time: '12:00', volume: 900 },
];

const participatingIps = [
  { ip: '185.228.101.34', hits: 8421, status: 'BLOCKED' },
  { ip: '185.228.101.35', hits: 7892, status: 'BLOCKED' },
  { ip: '45.134.26.108', hits: 6234, status: 'BLOCKED' },
  { ip: '45.134.26.109', hits: 5102, status: 'BLOCKED' },
  { ip: '91.240.118.42', hits: 4891, status: 'MONITORING' },
];

const affectedCustomers = [
  { name: 'Healthcare-A', attempts: 12421, status: 'ACTIVE' },
  { name: 'Finance-B', attempts: 9832, status: 'ACTIVE' },
  { name: 'Retail-C', attempts: 8421, status: 'PROTECTED' },
  { name: 'Healthcare-D', attempts: 6234, status: 'PROTECTED' },
  { name: 'E-commerce-E', attempts: 4102, status: 'PROTECTED' },
];

export default function CampaignDetailPage() {
  useDocumentTitle('SOC - Campaign Detail');
  const { id } = useParams();
  const campaigns = useHorizonStore((s) => s.campaigns);

  const campaign = useMemo(() => {
    return id ? campaigns.find((c) => c.id === id) : campaigns[0];
  }, [campaigns, id]);

  if (!campaign) {
    return (
      <div className="p-6">
        <div className="text-center py-20">
          <Target className="w-12 h-12 text-ink-muted mx-auto mb-4" />
          <h2 className="text-xl font-light text-ink-primary mb-2">
            No Campaign Selected
          </h2>
          <p className="text-ink-secondary">
            Select a campaign from the overview to view details
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Breadcrumb items={[
        { label: 'Campaigns', to: '/campaigns' },
        { label: campaign.name },
      ]} />
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <Link to="/campaigns" className="text-sm text-link hover:text-link-hover flex items-center gap-1">
            <ChevronRight className="w-4 h-4 rotate-180" />
            Back to Campaigns
          </Link>
          <div className="mt-2 flex items-center gap-3 flex-wrap">
            <h1 className="text-3xl font-light text-ink-primary">{campaign.name}</h1>
            <span
              className={clsx(
                'px-2 py-0.5 text-xs border',
                campaign.severity === 'CRITICAL' && 'bg-ac-red/15 text-ac-red border-ac-red/40',
                campaign.severity === 'HIGH' && 'bg-ac-orange/20 text-ac-orange border-ac-orange/40',
                campaign.severity === 'MEDIUM' && 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
                campaign.severity === 'LOW' && 'bg-ac-blue/10 text-ac-blue border-ac-blue/30'
              )}
            >
              {campaign.severity}
            </span>
            {campaign.isCrossTenant && (
              <span className="px-2 py-0.5 text-xs border bg-ac-purple/10 text-ac-purple border-ac-purple/30">
                Cross-Tenant
              </span>
            )}
          </div>
          <p className="text-ink-secondary mt-2">
            {campaign.description || 'Coordinated attack campaign detected by Signal Horizon'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-outline h-10 px-4 text-xs">
            <ExternalLink className="w-4 h-4 mr-2" />
            Export IOCs
          </button>
          <button className="btn-primary h-10 px-4 text-xs">
            <Shield className="w-4 h-4 mr-2" />
            Open War Room
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatMini icon={Users} label="Customers" value={campaign.tenantsAffected.toString()} />
        <StatMini icon={Activity} label="Confidence" value={`${Math.round(campaign.confidence * 100)}%`} />
        <StatMini icon={Clock} label="First Seen" value={new Date(campaign.firstSeenAt).toLocaleDateString()} />
        <StatMini icon={Flame} label="Total Attempts" value="47,832" />
      </div>

      {/* Campaign Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
           <ErrorBoundary>
             <CampaignGraph campaignId={id} />
           </ErrorBoundary>
        </div>
        
        <div className="space-y-6">
          <div className="card p-6">
            <h3 className="text-sm font-medium text-ink-secondary mb-4">Campaign Intelligence</h3>
             <div className="space-y-4">
               <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                 <span className="text-sm text-ink-muted">Confidence</span>
                 <span className="text-sm font-medium text-ac-green">98%</span>
               </div>
               <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                 <span className="text-sm text-ink-muted">Attribution</span>
                 <span className="text-sm font-medium text-ink-primary">APT-29</span>
               </div>
               <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                 <span className="text-sm text-ink-muted">Targeting</span>
                 <span className="text-sm font-medium text-ink-primary">Finance, Govt</span>
               </div>
               <div className="pt-2 text-xs text-ink-muted">
                 Automated graph correlation identified 3 distinct IP clusters associated with this campaign.
               </div>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Timeline */}
      <section className="card">
        <div className="card-header">
          <h2 className="font-medium text-ink-primary">Attack Timeline</h2>
        </div>
        <div className="card-body h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={attackTimeline}>
              <CartesianGrid stroke="rgba(0, 87, 183, 0.15)" strokeDasharray="4 4" vertical={false} />
              <XAxis dataKey="time" stroke="#7B8FA8" tick={{ fill: '#7B8FA8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis stroke="#7B8FA8" tick={{ fill: '#7B8FA8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={TOOLTIP_CONTENT_STYLE}
                labelStyle={TOOLTIP_LABEL_STYLE}
                itemStyle={TOOLTIP_ITEM_STYLE}
              />
              <Area type="monotone" dataKey="volume" stroke="var(--ac-red)" fill="var(--ac-red)" fillOpacity={0.25} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Participating IPs */}
        <section className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="font-medium text-ink-primary">Participating IPs</h2>
            <button className="btn-outline h-8 px-3 text-xs">Block All</button>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hits</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {participatingIps.map((ip) => (
                  <tr key={ip.ip}>
                    <td className="font-mono text-sm text-ink-primary">{ip.ip}</td>
                    <td className="text-ink-secondary">{ip.hits.toLocaleString()}</td>
                    <td>
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs border',
                          ip.status === 'BLOCKED'
                            ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                            : 'bg-ac-orange/10 text-ac-orange border-ac-orange/30'
                        )}
                      >
                        {ip.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Affected Customers */}
        <section className="card">
          <div className="card-header flex items-center justify-between">
            <h2 className="font-medium text-ink-primary">Affected Customers</h2>
            <button className="btn-outline h-8 px-3 text-xs">View All</button>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Attempts</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {affectedCustomers.map((customer) => (
                  <tr key={customer.name}>
                    <td className="text-ink-primary">{customer.name}</td>
                    <td className="text-ink-secondary">{customer.attempts.toLocaleString()}</td>
                    <td>
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs border',
                          customer.status === 'ACTIVE'
                            ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                            : 'bg-ac-green/10 text-ac-green border-ac-green/30'
                        )}
                      >
                        {customer.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Correlation Signals */}
      <section className="card">
        <div className="card-header">
          <h2 className="font-medium text-ink-primary">Correlation Signals</h2>
        </div>
        <div className="card-body space-y-4">
          {mockCorrelationSignals.map((signal) => (
            <div key={signal.name} className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-ink-secondary">{signal.name}</span>
                <span className="text-ink-primary font-medium">
                  {Math.round(signal.confidence * 100)}%
                </span>
              </div>
              <div className="h-2 bg-surface-subtle border border-border-subtle">
                <div
                  className={clsx('h-2', signal.color)}
                  style={{ width: `${signal.confidence * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Response Actions */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <ActionButton icon={Swords} label="Block All IPs" tone="bg-ac-red" />
        <ActionButton icon={Shield} label="Block Fingerprint" tone="bg-ac-red" />
        <ActionButton icon={Activity} label="Block ASN" tone="bg-ac-red" />
        <ActionButton icon={Flame} label="Challenge Mode" tone="bg-ac-orange" />
        <ActionButton icon={ExternalLink} label="Export IOCs" tone="bg-ac-blue" />
        <ActionButton icon={Users} label="Notify Customers" tone="bg-ac-blue" />
      </section>
    </div>
  );
}

function StatMini({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
}) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <div className="w-10 h-10 border border-border-subtle flex items-center justify-center text-ac-blue">
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <div className="text-xs tracking-[0.18em] uppercase text-ink-muted">{label}</div>
        <div className="text-xl font-light text-ink-primary">{value}</div>
      </div>
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  tone,
}: {
  icon: React.ElementType;
  label: string;
  tone: string;
}) {
  return (
    <button className={clsx('px-4 py-3 text-sm font-medium text-ac-white flex items-center gap-2 transition-colors hover:brightness-110', tone)}>
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}
