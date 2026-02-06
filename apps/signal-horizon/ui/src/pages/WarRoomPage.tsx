/**
 * War Room Page
 * Real-time collaboration for incident response
 */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Users,
  Clock,
  Send,
} from 'lucide-react';
import { clsx } from 'clsx';
import { PlaybookSelector, type Playbook } from '../components/warroom/PlaybookSelector';
import { PlaybookRunner } from '../components/warroom/PlaybookRunner';

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

// ======================== Main Component ========================
export default function WarRoomPage() {
  useDocumentTitle('War Room');
  const { id } = useParams();
  const [message, setMessage] = useState('');
  const [activePlaybook, setActivePlaybook] = useState<Playbook | null>(null);

  const handlePlaybookComplete = () => {
    // In a real app, this would add an activity log
    console.log('Playbook completed');
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-ac-red/40 bg-ac-red text-ac-white">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-light text-ac-white flex items-center gap-2">
              <Users className="w-5 h-5 text-ac-white" />
              {id ? `War Room: ${id}` : 'Dark Phoenix Response'}
            </h1>
            <p className="text-sm text-ac-white/80 mt-1">
              Incident response for Operation Dark Phoenix campaign
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex -space-x-2">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="w-8 h-8 bg-ac-white/15 border-2 border-ac-white/30 flex items-center justify-center text-xs font-medium"
                >
                  U{i}
                </div>
              ))}
            </div>
            <span className="text-sm text-ac-white/80">3 participants</span>
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Activity Feed */}
        <div className="flex-1 flex flex-col">
          <div className="grid grid-cols-3 gap-4 p-4 border-b border-border-subtle">
            <MetricTile label="Attacks/Min" value="847" tone="bg-ac-red" />
            <MetricTile label="Block Rate" value="94%" tone="bg-ac-green" />
            <MetricTile label="New IPs (5min)" value="3" tone="bg-ac-orange" />
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {mockActivities.map((activity) => (
              <ActivityItem key={activity.id} activity={activity} />
            ))}
          </div>

          {/* Message Input */}
          <div className="p-4 border-t border-border-subtle">
            <div className="flex gap-2">
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type a message..."
                aria-label="War room message"
                className="flex-1 bg-surface-inset border border-border-subtle px-4 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue"
              />
              <button className="btn-primary h-10 px-4">
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="w-80 border-l border-border-subtle p-4 space-y-6 bg-surface-subtle overflow-y-auto">
          {/* Playbooks */}
          <div>
            {activePlaybook ? (
              <PlaybookRunner
                playbook={activePlaybook}
                onClose={() => setActivePlaybook(null)}
                onComplete={handlePlaybookComplete}
              />
            ) : (
              <PlaybookSelector onSelect={setActivePlaybook} />
            )}
          </div>

          {/* Live Metrics */}
          <div>
            <h3 className="text-sm font-semibold text-ink-muted mb-3">
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
            <h3 className="text-sm font-semibold text-ink-muted mb-3">
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
          'w-8 h-8 flex items-center justify-center text-xs font-medium flex-shrink-0',
          isBot && 'bg-ac-blue/10 text-ac-blue',
          isSystem && 'bg-surface-subtle text-ink-muted',
          !isBot && !isSystem && 'bg-surface-subtle text-ink-primary'
        )}
      >
        {isBot ? 'HB' : isSystem ? 'SY' : activity.actor[0]}
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'font-medium',
              isBot && 'text-ac-blue',
              !isBot && 'text-ink-primary'
            )}
          >
            {activity.actor}
          </span>
          <span className="text-xs text-ink-muted">
            {activity.action.replace('_', ' ')}
          </span>
        </div>
        <p className="text-sm text-ink-secondary mt-1">{activity.description}</p>
        <div className="flex items-center gap-1 mt-1 text-xs text-ink-muted">
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
    <div className="flex items-center justify-between p-2 border border-border-subtle bg-surface-base">
      <span className="text-sm text-ink-secondary">{label}</span>
      <div className="text-right">
        <span className="text-ink-primary font-medium">{value}</span>
        <span className="text-xs text-ink-muted ml-1">{unit}</span>
      </div>
    </div>
  );
}

function MetricTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="card p-4">
      <div className="text-xs tracking-[0.18em] uppercase text-ink-muted">{label}</div>
      <div className="mt-2 flex items-end gap-3">
        <span className="text-3xl font-light text-ink-primary">{value}</span>
        <span className={clsx('h-1 flex-1', tone)} />
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
    <div className="flex items-center justify-between p-2 border border-border-subtle bg-surface-base">
      <span className="text-sm text-ink-secondary">{name}</span>
      <span
        className={clsx(
          'text-xs px-2 py-0.5 border',
          status === 'protected' && 'bg-ac-green/10 text-ac-green border-ac-green/30',
          status === 'monitoring' && 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
          status === 'at-risk' && 'bg-ac-red/10 text-ac-red border-ac-red/30'
        )}
      >
        {status}
      </span>
    </div>
  );
}
