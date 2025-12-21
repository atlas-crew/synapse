/**
 * Threat Overview Page
 * Live attack map, threat feed, sensor status, active campaigns
 */

import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  Activity,
  Server,
  TrendingUp,
  Globe,
} from 'lucide-react';
import { useHorizonStore } from '../stores/horizonStore';
import { clsx } from 'clsx';
import { StatsGridSkeleton, CampaignListSkeleton, AlertFeedSkeleton, TableSkeleton } from '../components/LoadingStates';

const severityColors = {
  LOW: 'text-green-400 bg-green-500/20 border-green-500/30',
  MEDIUM: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
  HIGH: 'text-orange-400 bg-orange-500/20 border-orange-500/30',
  CRITICAL: 'text-red-400 bg-red-500/20 border-red-500/30',
};

export default function OverviewPage() {
  const { campaigns, threats, alerts, stats, isLoading } = useHorizonStore();

  // Show loading skeletons while initial data loads
  if (isLoading) {
    return (
      <div className="p-6 space-y-6" role="main" aria-busy="true" aria-label="Loading threat overview">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Threat Overview</h1>
            <p className="text-gray-400 mt-1">Loading fleet intelligence...</p>
          </div>
        </div>
        <StatsGridSkeleton />
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <CampaignListSkeleton />
          </div>
          <AlertFeedSkeleton />
        </div>
        <TableSkeleton rows={5} />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Threat overview dashboard">
      {/* Header */}
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Overview</h1>
          <p className="text-gray-400 mt-1">
            Real-time fleet intelligence across {stats.sensorsOnline} sensors
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm" role="status" aria-live="polite">
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
          <span className="text-gray-400">Live</span>
          <span className="sr-only">Dashboard is receiving live updates</span>
        </div>
      </header>

      {/* Stats Grid */}
      <section aria-label="Key metrics" className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Shield}
          label="Fleet Threats"
          value={stats.fleetThreats}
          color="text-horizon-400"
          bgColor="bg-horizon-500/10"
        />
        <StatCard
          icon={AlertTriangle}
          label="Active Campaigns"
          value={stats.activeCampaigns}
          color="text-orange-400"
          bgColor="bg-orange-500/10"
        />
        <StatCard
          icon={Activity}
          label="Blocked Indicators"
          value={stats.blockedIndicators}
          color="text-green-400"
          bgColor="bg-green-500/10"
        />
        <StatCard
          icon={Server}
          label="Sensors Online"
          value={stats.sensorsOnline}
          color="text-blue-400"
          bgColor="bg-blue-500/10"
        />
      </section>

      <div className="grid grid-cols-3 gap-6">
        {/* Active Campaigns */}
        <section className="col-span-2 card" aria-labelledby="campaigns-heading">
          <div className="card-header flex items-center justify-between">
            <h2 id="campaigns-heading" className="font-semibold text-white">Active Campaigns</h2>
            <span className="text-xs text-gray-500" aria-label={`${campaigns.length} active campaigns`}>
              {campaigns.length} active
            </span>
          </div>
          <div className="card-body" role="list" aria-label="Campaign list">
            {campaigns.length === 0 ? (
              <div className="text-center text-gray-500 py-8" role="status">
                No active campaigns detected
              </div>
            ) : (
              <div className="space-y-3">
                {campaigns.slice(0, 5).map((campaign) => (
                  <motion.div
                    key={campaign.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    role="listitem"
                    tabIndex={0}
                    aria-label={`Campaign: ${campaign.name}, Severity: ${campaign.severity}, ${campaign.tenantsAffected} tenants affected`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        // Navigate to campaign detail - would use navigate() from useNavigate
                        e.preventDefault();
                      }
                    }}
                    className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg hover:bg-gray-800 transition-colors cursor-pointer focus:outline-none focus:ring-2 focus:ring-horizon-500 focus:ring-offset-2 focus:ring-offset-gray-900"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={clsx(
                          'w-2 h-2 rounded-full',
                          campaign.severity === 'CRITICAL' && 'bg-red-500',
                          campaign.severity === 'HIGH' && 'bg-orange-500',
                          campaign.severity === 'MEDIUM' && 'bg-yellow-500',
                          campaign.severity === 'LOW' && 'bg-green-500'
                        )}
                        aria-hidden="true"
                      />
                      <div>
                        <div className="font-medium text-white">
                          {campaign.name}
                        </div>
                        <div className="text-xs text-gray-400">
                          <span className="sr-only">Affects </span>
                          {campaign.tenantsAffected} tenants • {Math.round(campaign.confidence * 100)}% confidence
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {campaign.isCrossTenant && (
                        <span className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded">
                          Cross-Tenant
                        </span>
                      )}
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs rounded border',
                          severityColors[campaign.severity]
                        )}
                      >
                        {campaign.severity}
                      </span>
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Threat Feed */}
        <section className="card" aria-labelledby="threat-feed-heading" aria-live="polite">
          <div className="card-header flex items-center justify-between">
            <h2 id="threat-feed-heading" className="font-semibold text-white">Live Threat Feed</h2>
            <TrendingUp className="w-4 h-4 text-gray-500" aria-hidden="true" />
          </div>
          <div className="card-body max-h-80 overflow-y-auto" role="log" aria-label="Recent threat alerts">
            {alerts.length === 0 ? (
              <div className="text-center text-gray-500 py-8" role="status">
                No recent alerts
              </div>
            ) : (
              <div className="space-y-2">
                {alerts.slice(0, 10).map((alert) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={clsx(
                      'p-2 rounded text-xs border-l-2',
                      alert.severity === 'CRITICAL' && 'border-l-red-500 bg-red-500/5',
                      alert.severity === 'HIGH' && 'border-l-orange-500 bg-orange-500/5',
                      alert.severity === 'MEDIUM' && 'border-l-yellow-500 bg-yellow-500/5',
                      alert.severity === 'LOW' && 'border-l-green-500 bg-green-500/5'
                    )}
                  >
                    <div className="font-medium text-white">{alert.title}</div>
                    <div className="text-gray-400 mt-0.5">{alert.description}</div>
                    <div className="text-gray-500 mt-1">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Recent Threats Table */}
      <section className="card" aria-labelledby="threats-heading">
        <div className="card-header flex items-center justify-between">
          <h2 id="threats-heading" className="font-semibold text-white">Recent Threats</h2>
          <span className="text-xs text-gray-500" aria-label={`${threats.length} total threats`}>{threats.length} threats</span>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table" role="table" aria-label="Recent threat indicators">
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Indicator</th>
                <th scope="col">Risk Score</th>
                <th scope="col">Hits</th>
                <th scope="col">Tenants</th>
                <th scope="col">Scope</th>
                <th scope="col">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {threats.slice(0, 10).map((threat) => (
                <tr key={threat.id}>
                  <td>
                    <span className="px-2 py-0.5 text-xs bg-gray-700 rounded">
                      {threat.threatType}
                    </span>
                  </td>
                  <td className="font-mono text-sm">{threat.indicator}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div
                        className={clsx(
                          'w-12 h-1.5 rounded-full overflow-hidden bg-gray-700'
                        )}
                      >
                        <div
                          className={clsx(
                            'h-full rounded-full',
                            threat.riskScore >= 80 && 'bg-red-500',
                            threat.riskScore >= 60 && threat.riskScore < 80 && 'bg-orange-500',
                            threat.riskScore >= 40 && threat.riskScore < 60 && 'bg-yellow-500',
                            threat.riskScore < 40 && 'bg-green-500'
                          )}
                          style={{ width: `${threat.riskScore}%` }}
                        />
                      </div>
                      <span className="text-sm">{threat.riskScore.toFixed(1)}</span>
                    </div>
                  </td>
                  <td>{threat.hitCount.toLocaleString()}</td>
                  <td>{threat.tenantsAffected}</td>
                  <td>
                    {threat.isFleetThreat ? (
                      <span className="flex items-center gap-1 text-purple-400">
                        <Globe className="w-3 h-3" />
                        Fleet
                      </span>
                    ) : (
                      <span className="text-gray-500">Local</span>
                    )}
                  </td>
                  <td className="text-gray-400 text-sm">
                    {new Date(threat.lastSeenAt).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  bgColor,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
  bgColor: string;
}) {
  return (
    <article
      className="card p-4"
      aria-label={`${label}: ${value.toLocaleString()}`}
      tabIndex={0}
    >
      <div className="flex items-center gap-3">
        <div className={clsx('p-2 rounded-lg', bgColor)} aria-hidden="true">
          <Icon className={clsx('w-5 h-5', color)} />
        </div>
        <div>
          <div className="stat-value" aria-hidden="true">{value.toLocaleString()}</div>
          <div className="stat-label">{label}</div>
        </div>
      </div>
    </article>
  );
}
