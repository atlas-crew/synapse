/**
 * Global Intel Page
 * Attack volume trends, trending threats, IOC table, export
 */

import { useState } from 'react';
import {
  BarChart3,
  TrendingUp,
  Download,
  Calendar,
  FileJson,
  FileText,
  Shield,
} from 'lucide-react';
import { clsx } from 'clsx';

const timeRanges = ['24h', '7d', '30d', '90d'];

const trendingThreats = [
  { type: 'Credential Stuffing', change: +45, volume: 12450 },
  { type: 'API Abuse', change: +23, volume: 8920 },
  { type: 'Bot Traffic', change: +12, volume: 45230 },
  { type: 'DDoS Attempts', change: -8, volume: 2340 },
  { type: 'SQL Injection', change: -15, volume: 890 },
];

const mockIOCs = [
  { indicator: '192.168.1.100', type: 'IP', severity: 'HIGH', campaigns: 2 },
  { indicator: 'fp-dark-phoenix-001', type: 'FINGERPRINT', severity: 'CRITICAL', campaigns: 1 },
  { indicator: 'AS12345', type: 'ASN', severity: 'MEDIUM', campaigns: 3 },
  { indicator: 'Mozilla/5.0 (Bot)', type: 'USER_AGENT', severity: 'LOW', campaigns: 1 },
  { indicator: '10.0.0.0/8', type: 'IP_RANGE', severity: 'MEDIUM', campaigns: 2 },
];

export default function IntelPage() {
  const [timeRange, setTimeRange] = useState('7d');

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Global Intelligence</h1>
          <p className="text-gray-400 mt-1">
            Fleet-wide attack trends and IOC export
          </p>
        </div>
        <div className="flex items-center gap-4">
          {/* Time Range Selector */}
          <div className="flex items-center gap-1 bg-gray-800 rounded-lg p-1">
            {timeRanges.map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={clsx(
                  'px-3 py-1.5 text-sm rounded-md transition-colors',
                  timeRange === range
                    ? 'bg-horizon-600 text-white'
                    : 'text-gray-400 hover:text-white'
                )}
              >
                {range}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Shield}
          label="Total Threats"
          value="156,234"
          change="+12%"
          positive={false}
        />
        <StatCard
          icon={TrendingUp}
          label="Blocked Attacks"
          value="89,456"
          change="+28%"
          positive={true}
        />
        <StatCard
          icon={BarChart3}
          label="Active Campaigns"
          value="23"
          change="-5%"
          positive={true}
        />
        <StatCard
          icon={Calendar}
          label="Fleet IOCs"
          value="4,567"
          change="+8%"
          positive={false}
        />
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Attack Volume Chart Placeholder */}
        <div className="col-span-2 card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Attack Volume Trends</h2>
          </div>
          <div className="card-body">
            <div className="h-64 flex items-center justify-center text-gray-500">
              <div className="text-center">
                <BarChart3 className="w-12 h-12 mx-auto mb-2 text-gray-600" />
                <p>Chart visualization placeholder</p>
                <p className="text-sm">Integrate with Recharts for production</p>
              </div>
            </div>
          </div>
        </div>

        {/* Trending Threats */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Trending Threats</h2>
          </div>
          <div className="card-body space-y-3">
            {trendingThreats.map((threat) => (
              <div
                key={threat.type}
                className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg"
              >
                <div>
                  <div className="text-sm text-white">{threat.type}</div>
                  <div className="text-xs text-gray-500">
                    {threat.volume.toLocaleString()} events
                  </div>
                </div>
                <span
                  className={clsx(
                    'text-sm font-medium',
                    threat.change > 0 ? 'text-red-400' : 'text-green-400'
                  )}
                >
                  {threat.change > 0 ? '+' : ''}
                  {threat.change}%
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h2 className="font-semibold text-white">Indicators of Compromise</h2>
          <div className="flex gap-2">
            <button className="btn-ghost text-sm py-1">
              <FileJson className="w-4 h-4 mr-1" />
              JSON
            </button>
            <button className="btn-ghost text-sm py-1">
              <FileText className="w-4 h-4 mr-1" />
              CSV
            </button>
            <button className="btn-primary text-sm py-1">
              <Download className="w-4 h-4 mr-1" />
              STIX 2.1
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Campaigns</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockIOCs.map((ioc, i) => (
                <tr key={i}>
                  <td className="font-mono text-sm text-white">
                    {ioc.indicator}
                  </td>
                  <td>
                    <span className="px-2 py-0.5 text-xs bg-gray-700 rounded">
                      {ioc.type}
                    </span>
                  </td>
                  <td>
                    <span
                      className={clsx(
                        'px-2 py-0.5 text-xs rounded border',
                        ioc.severity === 'CRITICAL' &&
                          'text-red-400 bg-red-500/20 border-red-500/30',
                        ioc.severity === 'HIGH' &&
                          'text-orange-400 bg-orange-500/20 border-orange-500/30',
                        ioc.severity === 'MEDIUM' &&
                          'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
                        ioc.severity === 'LOW' &&
                          'text-green-400 bg-green-500/20 border-green-500/30'
                      )}
                    >
                      {ioc.severity}
                    </span>
                  </td>
                  <td>{ioc.campaigns}</td>
                  <td>
                    <button className="text-sm text-horizon-400 hover:text-horizon-300">
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  change,
  positive,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  change: string;
  positive: boolean;
}) {
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <div className="p-2 rounded-lg bg-gray-800">
          <Icon className="w-5 h-5 text-gray-400" />
        </div>
        <span
          className={clsx(
            'text-xs font-medium',
            positive ? 'text-green-400' : 'text-red-400'
          )}
        >
          {change}
        </span>
      </div>
      <div className="mt-3">
        <div className="text-2xl font-bold text-white">{value}</div>
        <div className="text-sm text-gray-400">{label}</div>
      </div>
    </div>
  );
}
