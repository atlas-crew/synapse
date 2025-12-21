/**
 * Campaign Detail Page
 * Timeline, participating actors, correlation signals, actions
 */

import { useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Target,
  Clock,
  Users,
  Shield,
  Activity,
  ExternalLink,
} from 'lucide-react';
import { useHorizonStore } from '../stores/horizonStore';
import { clsx } from 'clsx';

const mockCorrelationSignals = [
  { name: 'HTTP Fingerprint Match', confidence: 0.98, color: 'bg-purple-500' },
  { name: 'TLS Fingerprint Match', confidence: 0.95, color: 'bg-blue-500' },
  { name: 'Timing Pattern Match', confidence: 0.89, color: 'bg-green-500' },
  { name: 'User-Agent Pattern', confidence: 0.82, color: 'bg-yellow-500' },
];

export default function CampaignDetailPage() {
  const { id } = useParams();
  const campaigns = useHorizonStore((s) => s.campaigns);

  const campaign = id
    ? campaigns.find((c) => c.id === id)
    : campaigns[0]; // Default to first campaign

  if (!campaign) {
    return (
      <div className="p-6">
        <div className="text-center py-20">
          <Target className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">
            No Campaign Selected
          </h2>
          <p className="text-gray-400">
            Select a campaign from the overview to view details
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">{campaign.name}</h1>
            <span
              className={clsx(
                'px-2 py-0.5 text-xs rounded border',
                campaign.severity === 'CRITICAL' && 'text-red-400 bg-red-500/20 border-red-500/30',
                campaign.severity === 'HIGH' && 'text-orange-400 bg-orange-500/20 border-orange-500/30',
                campaign.severity === 'MEDIUM' && 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
                campaign.severity === 'LOW' && 'text-green-400 bg-green-500/20 border-green-500/30'
              )}
            >
              {campaign.severity}
            </span>
            {campaign.isCrossTenant && (
              <span className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded border border-purple-500/30">
                Cross-Tenant
              </span>
            )}
          </div>
          <p className="text-gray-400 mt-1">
            {campaign.description || 'Coordinated attack campaign detected by Signal Horizon'}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn-ghost">
            <ExternalLink className="w-4 h-4 mr-2" />
            Export IOCs
          </button>
          <button className="btn-primary">
            <Shield className="w-4 h-4 mr-2" />
            Block All
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <Users className="w-5 h-5 text-purple-400" />
            <div>
              <div className="text-2xl font-bold text-white">
                {campaign.tenantsAffected}
              </div>
              <div className="text-sm text-gray-400">Tenants Affected</div>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-horizon-400" />
            <div>
              <div className="text-2xl font-bold text-white">
                {Math.round(campaign.confidence * 100)}%
              </div>
              <div className="text-sm text-gray-400">Confidence</div>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-blue-400" />
            <div>
              <div className="text-2xl font-bold text-white">
                {new Date(campaign.firstSeenAt).toLocaleDateString()}
              </div>
              <div className="text-sm text-gray-400">First Seen</div>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <Target className="w-5 h-5 text-green-400" />
            <div>
              <div className="text-2xl font-bold text-white uppercase">
                {campaign.status}
              </div>
              <div className="text-sm text-gray-400">Status</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Correlation Signals */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Correlation Signals</h2>
          </div>
          <div className="card-body space-y-4">
            {mockCorrelationSignals.map((signal) => (
              <div key={signal.name} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-300">{signal.name}</span>
                  <span className="text-white font-medium">
                    {Math.round(signal.confidence * 100)}%
                  </span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${signal.confidence * 100}%` }}
                    transition={{ duration: 0.5, delay: 0.1 }}
                    className={clsx('h-full rounded-full', signal.color)}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Timeline */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Activity Timeline</h2>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              <TimelineItem
                time={campaign.lastActivityAt}
                title="Latest Activity"
                description="Campaign activity detected"
                type="activity"
              />
              <TimelineItem
                time={campaign.firstSeenAt}
                title="Campaign Detected"
                description="Cross-tenant pattern identified"
                type="detection"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function TimelineItem({
  time,
  title,
  description,
  type,
}: {
  time: string;
  title: string;
  description: string;
  type: 'detection' | 'activity' | 'block';
}) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div
          className={clsx(
            'w-3 h-3 rounded-full',
            type === 'detection' && 'bg-purple-500',
            type === 'activity' && 'bg-horizon-500',
            type === 'block' && 'bg-red-500'
          )}
        />
        <div className="w-0.5 flex-1 bg-gray-800" />
      </div>
      <div className="pb-4">
        <div className="text-sm font-medium text-white">{title}</div>
        <div className="text-xs text-gray-400">{description}</div>
        <div className="text-xs text-gray-500 mt-1">
          {new Date(time).toLocaleString()}
        </div>
      </div>
    </div>
  );
}
