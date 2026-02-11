/**
 * War Room Page
 * Real-time collaboration for incident response
 */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { useContextualCommands } from '../hooks/useContextualCommands';
import { useToast } from '../components/ui/Toast';
import { Clock, Send, UserPlus, Shield } from 'lucide-react';
import { PlaybookSelector, type Playbook } from '../components/warroom/PlaybookSelector';
import { PlaybookRunner } from '../components/warroom/PlaybookRunner';
import { Button, Input, alpha, colors } from '@/ui';

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
  const { toast } = useToast();

  useContextualCommands([
    {
      id: 'warroom-invite',
      label: 'Invite Participant',
      icon: UserPlus,
      metadata: 'Add a team member to this War Room',
      onSelect: () => toast.success('Invitation link copied to clipboard'),
    },
    {
      id: 'warroom-playbook',
      label: 'Execute Emergency Playbook',
      icon: Shield,
      metadata: 'Trigger rapid response workflow',
      onSelect: () => toast.info('Selecting emergency playbook...'),
    },
  ]);

  const handleSendMessage = () => {
    if (!message.trim()) return;
    toast.success('Message transmitted');
    setMessage('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      handleSendMessage();
    }
  };

  const handlePlaybookComplete = () => {
    // In a real app, this would add an activity log
    console.log('Playbook completed');
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header - Tactical War Room style */}
      <div
        className="p-5 border-b relative overflow-hidden surface-hero-gradient"
        style={{ borderColor: alpha(colors.red, 0.5), background: colors.navy }}
      >
        {/* Warning glow/scanline effect */}
        <div
          className="absolute inset-0 opacity-10 pointer-events-none scanlines"
          style={{ background: alpha(colors.red, 0.05) }}
        />

        <div className="relative z-10 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div
                className="w-2.5 h-2.5 animate-pulse"
                style={{ background: colors.red, boxShadow: `0 0 10px ${alpha(colors.red, 0.8)}` }}
              />
              <h1 className="text-2xl font-light text-white tracking-tight uppercase">
                {id ? `WAR ROOM: ${id}` : 'SIGNAL HORIZON: TACTICAL HUB'}
              </h1>
            </div>
            <p className="text-sm text-white/60 mt-1 max-w-2xl font-medium tracking-wide">
              Operation Dark Phoenix · Collective Response Active · Priority One Incident
            </p>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest mb-1">
                Participants
              </p>
              <div className="flex items-center gap-3">
                <div className="flex -space-x-2">
                  {[1, 2, 3].map((i) => (
                    <div
                      key={i}
                      className="w-8 h-8 rounded-none border border-white/20 flex items-center justify-center text-[10px] font-bold text-white/80 shadow-lg"
                      style={{ background: colors.navy }}
                    >
                      U{i}
                    </div>
                  ))}
                </div>
                <span className="text-xs font-mono text-white/80 font-bold">03_ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Activity Feed */}
        <div className="flex-1 flex flex-col bg-surface-base">
          <div className="grid grid-cols-3 gap-4 p-4 border-b border-border-subtle bg-surface-subtle/30">
            <MetricTile label="ATTACK FREQUENCY" value="847" tone="red" isAlert />
            <MetricTile label="MITIGATION RATE" value="94%" tone="green" />
            <MetricTile label="NEW INDICATORS" value="03" tone="orange" isWarning />
          </div>
          <div
            className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin"
            role="log"
            aria-live="polite"
            aria-relevant="additions"
            aria-atomic="false"
            aria-label="Activity feed"
          >
            {mockActivities.map((activity) => (
              <ActivityItem key={activity.id} activity={activity} />
            ))}
          </div>

          {/* Message Input */}
          <div className="p-4 border-t border-border-subtle bg-surface-subtle/50">
            <div className="flex gap-2">
              <div className="relative flex-1 group">
                <Input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Transmit message to tactical channel..."
                  aria-label="War room message"
                  size="md"
                />
                <div className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-ink-muted opacity-50 group-focus-within:opacity-100">
                  CTRL+ENTER TO SEND
                </div>
              </div>
              <Button
                size="md"
                onClick={handleSendMessage}
                icon={<Send aria-hidden="true" className="w-3.5 h-3.5" />}
                style={{ textTransform: 'uppercase', letterSpacing: '0.2em', fontSize: '10px' }}
              >
                Transmit
              </Button>
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
            <h3 className="text-sm font-semibold text-ink-muted mb-3">Live Metrics</h3>
            <div className="space-y-3">
              <MetricItem label="Attack Rate" value="1,234" unit="req/min" />
              <MetricItem label="Blocked" value="892" unit="requests" />
              <MetricItem label="Affected IPs" value="47" unit="unique" />
            </div>
          </div>

          {/* Customer Status */}
          <div>
            <h3 className="text-sm font-semibold text-ink-muted mb-3">Customer Status</h3>
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
  const badgeStyle = isBot
    ? {
        borderColor: alpha(colors.blue, 0.3),
        background: alpha(colors.blue, 0.1),
        color: colors.blue,
      }
    : isSystem
      ? {
          borderColor: alpha(colors.gray.mid, 0.3),
          background: alpha(colors.gray.mid, 0.1),
          color: colors.gray.mid,
        }
      : {
          borderColor: alpha(colors.navy, 0.2),
          background: alpha(colors.navy, 0.05),
          color: colors.navy,
        };

  return (
    <div className="flex gap-4 group">
      <div
        className="w-10 h-10 flex items-center justify-center text-[10px] font-bold flex-shrink-0 border transition-colors"
        style={badgeStyle}
      >
        {isBot ? 'HB' : isSystem ? 'SY' : activity.actor.substring(0, 2).toUpperCase()}
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-3">
          <span
            className="text-sm font-bold tracking-tight"
            style={{ color: isBot ? colors.blue : undefined }}
          >
            {activity.actor}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 bg-surface-subtle border border-border-subtle text-ink-muted font-bold uppercase tracking-tighter">
            {activity.action.replaceAll('_', ' ')}
          </span>
        </div>
        <p className="text-sm text-ink-primary font-medium mt-1 leading-relaxed">
          {activity.description}
        </p>
        <div className="flex items-center gap-1.5 mt-2 text-[10px] font-mono text-ink-muted uppercase tracking-widest">
          <Clock className="w-3 h-3" />
          {activity.timestamp.toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          })}
        </div>
      </div>
    </div>
  );
}

function MetricItem({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <div className="flex items-center justify-between p-3 border border-border-subtle bg-surface-base shadow-inner">
      <span className="text-[10px] font-bold text-ink-secondary uppercase tracking-widest">
        {label}
      </span>
      <div className="text-right">
        <span className="text-sm font-mono font-bold text-ink-primary">{value}</span>
        <span className="text-[9px] font-bold text-ink-muted uppercase ml-1.5 tracking-tighter">
          {unit}
        </span>
      </div>
    </div>
  );
}

function MetricTile({
  label,
  value,
  tone,
  isAlert,
  isWarning,
}: {
  label: string;
  value: string;
  tone: 'red' | 'green' | 'orange';
  isAlert?: boolean;
  isWarning?: boolean;
}) {
  const toneColor = tone === 'red' ? colors.red : tone === 'green' ? colors.green : colors.orange;
  const tileStyle = isAlert
    ? {
        borderColor: alpha(colors.red, 0.5),
        boxShadow: `0 0 15px ${alpha(colors.red, 0.15)}`,
        background: alpha(colors.red, 0.02),
      }
    : isWarning
      ? {
          borderColor: alpha(colors.orange, 0.5),
          boxShadow: `0 0 15px ${alpha(colors.orange, 0.1)}`,
          background: alpha(colors.orange, 0.02),
        }
      : undefined;

  return (
    <div className="card p-5 transition-all duration-300 border-border-subtle" style={tileStyle}>
      <div className="text-[10px] font-bold tracking-[0.2em] uppercase text-ink-muted mb-2">
        {label}
      </div>
      <div className="flex items-end justify-between gap-4">
        <span
          className="text-3xl font-light"
          style={{ color: isAlert ? colors.red : isWarning ? colors.orange : undefined }}
        >
          {value}
        </span>
        <div
          className={`h-1 flex-1 mb-2 ${isAlert || isWarning ? 'animate-pulse' : ''}`}
          style={{ background: toneColor }}
        />
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
  const statusStyle =
    status === 'protected'
      ? {
          background: alpha(colors.green, 0.1),
          color: colors.green,
          borderColor: alpha(colors.green, 0.3),
        }
      : status === 'monitoring'
        ? {
            background: alpha(colors.orange, 0.1),
            color: colors.orange,
            borderColor: alpha(colors.orange, 0.3),
          }
        : {
            background: alpha(colors.red, 0.1),
            color: colors.red,
            borderColor: alpha(colors.red, 0.3),
          };

  return (
    <div className="flex items-center justify-between p-3 border border-border-subtle bg-surface-base hover:bg-surface-subtle transition-colors">
      <span className="text-xs font-medium text-ink-primary">{name}</span>
      <span
        className="text-[9px] px-2 py-0.5 border font-bold uppercase tracking-widest"
        style={statusStyle}
      >
        {status}
      </span>
    </div>
  );
}
