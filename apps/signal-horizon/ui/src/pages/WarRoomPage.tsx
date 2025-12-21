/**
 * War Room Page
 * Real-time collaboration for incident response
 */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Users,
  Shield,
  Ban,
  AlertTriangle,
  Send,
  Clock,
} from 'lucide-react';
import { clsx } from 'clsx';

interface Activity {
  id: string;
  actor: string;
  actorType: 'user' | 'bot' | 'system';
  action: string;
  description: string;
  timestamp: Date;
}

const mockActivities: Activity[] = [
  {
    id: '1',
    actor: '@horizon-bot',
    actorType: 'bot',
    action: 'ALERT_TRIGGERED',
    description: 'Cross-tenant campaign detected: Operation Dark Phoenix',
    timestamp: new Date(Date.now() - 3600000),
  },
  {
    id: '2',
    actor: '@horizon-bot',
    actorType: 'bot',
    action: 'BLOCK_CREATED',
    description: 'Auto-blocked IP 192.168.1.100 (fleet-wide)',
    timestamp: new Date(Date.now() - 3500000),
  },
  {
    id: '3',
    actor: 'Security Lead',
    actorType: 'user',
    action: 'MESSAGE',
    description: 'Confirmed attack pattern matches known APT group tactics',
    timestamp: new Date(Date.now() - 3000000),
  },
  {
    id: '4',
    actor: '@horizon-bot',
    actorType: 'bot',
    action: 'BLOCK_CREATED',
    description: 'Auto-blocked fingerprint fp-dark-phoenix-001',
    timestamp: new Date(Date.now() - 2500000),
  },
];

const quickActions = [
  { icon: Ban, label: 'Block IP', color: 'text-red-400' },
  { icon: Shield, label: 'Block Fingerprint', color: 'text-orange-400' },
  { icon: AlertTriangle, label: 'Block ASN', color: 'text-yellow-400' },
];

export default function WarRoomPage() {
  const { id } = useParams();
  const [message, setMessage] = useState('');

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-horizon-400" />
              {id ? `War Room: ${id}` : 'Dark Phoenix Response'}
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Incident response for Operation Dark Phoenix campaign
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex -space-x-2">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="w-8 h-8 rounded-full bg-gray-700 border-2 border-gray-900 flex items-center justify-center text-xs font-medium"
                >
                  U{i}
                </div>
              ))}
            </div>
            <span className="text-sm text-gray-400">3 participants</span>
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Activity Feed */}
        <div className="flex-1 flex flex-col">
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {mockActivities.map((activity) => (
              <ActivityItem key={activity.id} activity={activity} />
            ))}
          </div>

          {/* Message Input */}
          <div className="p-4 border-t border-gray-800">
            <div className="flex gap-2">
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type a message..."
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-horizon-500"
              />
              <button className="btn-primary">
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="w-80 border-l border-gray-800 p-4 space-y-6">
          {/* Quick Actions */}
          <div>
            <h3 className="text-sm font-semibold text-gray-400 mb-3">
              Quick Actions
            </h3>
            <div className="space-y-2">
              {quickActions.map((action) => (
                <button
                  key={action.label}
                  className="w-full flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors"
                >
                  <action.icon className={clsx('w-4 h-4', action.color)} />
                  <span className="text-gray-300">{action.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Live Metrics */}
          <div>
            <h3 className="text-sm font-semibold text-gray-400 mb-3">
              Live Metrics
            </h3>
            <div className="space-y-3">
              <MetricItem label="Attack Rate" value="1,234" unit="req/min" />
              <MetricItem label="Blocked" value="892" unit="requests" />
              <MetricItem label="Affected IPs" value="47" unit="unique" />
            </div>
          </div>

          {/* Customer Status */}
          <div>
            <h3 className="text-sm font-semibold text-gray-400 mb-3">
              Customer Status
            </h3>
            <div className="space-y-2">
              <CustomerStatus name="Acme Corp" status="protected" />
              <CustomerStatus name="Globex Industries" status="protected" />
              <CustomerStatus name="Initech LLC" status="monitoring" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityItem({ activity }: { activity: Activity }) {
  const isBot = activity.actorType === 'bot';
  const isSystem = activity.actorType === 'system';

  return (
    <div className="flex gap-3">
      <div
        className={clsx(
          'w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0',
          isBot && 'bg-horizon-600/20 text-horizon-400',
          isSystem && 'bg-gray-700 text-gray-400',
          !isBot && !isSystem && 'bg-gray-700 text-white'
        )}
      >
        {isBot ? 'HB' : isSystem ? 'SY' : activity.actor[0]}
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'font-medium',
              isBot && 'text-horizon-400',
              !isBot && 'text-white'
            )}
          >
            {activity.actor}
          </span>
          <span className="text-xs text-gray-500">
            {activity.action.replace('_', ' ')}
          </span>
        </div>
        <p className="text-sm text-gray-300 mt-1">{activity.description}</p>
        <div className="flex items-center gap-1 mt-1 text-xs text-gray-500">
          <Clock className="w-3 h-3" />
          {activity.timestamp.toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
}

function MetricItem({
  label,
  value,
  unit,
}: {
  label: string;
  value: string;
  unit: string;
}) {
  return (
    <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
      <span className="text-sm text-gray-400">{label}</span>
      <div className="text-right">
        <span className="text-white font-medium">{value}</span>
        <span className="text-xs text-gray-500 ml-1">{unit}</span>
      </div>
    </div>
  );
}

function CustomerStatus({
  name,
  status,
}: {
  name: string;
  status: 'protected' | 'monitoring' | 'at-risk';
}) {
  return (
    <div className="flex items-center justify-between p-2 bg-gray-800/50 rounded-lg">
      <span className="text-sm text-gray-300">{name}</span>
      <span
        className={clsx(
          'text-xs px-2 py-0.5 rounded',
          status === 'protected' && 'bg-green-500/20 text-green-400',
          status === 'monitoring' && 'bg-yellow-500/20 text-yellow-400',
          status === 'at-risk' && 'bg-red-500/20 text-red-400'
        )}
      >
        {status}
      </span>
    </div>
  );
}
