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
import { PlaybookSelector } from '../components/warroom/PlaybookSelector';
import type { Playbook } from '../data/playbooks';
import { PlaybookRunner } from '../components/warroom/PlaybookRunner';
import { 
  Button, 
  Input, 
  SectionHeader, 
  Stack, 
  alpha, 
  colors,
  Box,
  Text,
  PAGE_TITLE_STYLE,
} from '@/ui';

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
    console.log('Playbook completed');
  };

  return (
    <Box flex direction="column" style={{ height: '100%' }}>
      {/* Header - Tactical War Room style */}
      <Box
        p="lg"
        border="bottom"
        style={{ 
          borderColor: alpha(colors.red, 0.5), 
          background: 'var(--bg)',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        {/* Warning glow/scanline effect */}
        <Box
          style={{ 
            position: 'absolute',
            inset: 0,
            opacity: 0.1,
            pointerEvents: 'none',
            background: `radial-gradient(circle at 50% -20%, var(--ac-red) 0%, transparent 70%)`
          }}
        />

        <Stack direction="row" align="center" justify="space-between" style={{ position: 'relative', zIndex: 1 }}>
          <Box>
            <Stack direction="row" align="center" gap="md">
              <SectionHeader
                title={id ? `War Room: ${id}` : 'Tactical Hub'}
                icon={(
                  <Box
                    className="w-2.5 h-2.5 animate-pulse"
                    style={{ background: 'var(--ac-red)', boxShadow: `0 0 10px var(--ac-red)` }}
                  />
                )}
                size="h2"
                style={{ marginBottom: 0 }}
                titleStyle={PAGE_TITLE_STYLE}
              />
            </Stack>
            <Text variant="body" color="secondary" style={{ marginTop: '4px', letterSpacing: '0.05em' }}>
              Operation Dark Phoenix · Collective Response Active · Priority One Incident
            </Text>
          </Box>
          <Box style={{ textAlign: 'right' }}>
            <Text variant="label" color="secondary" style={{ fontSize: '10px', opacity: 0.5 }}>
              PARTICIPANTS
            </Text>
            <Stack direction="row" align="center" gap="md" style={{ marginTop: '4px' }}>
              <Stack direction="row" gap="none">
                {[1, 2, 3].map((i) => (
                  <Box
                    key={i}
                    style={{ 
                      width: 32, 
                      height: 32, 
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      background: 'var(--surface)',
                      marginLeft: i > 1 ? -8 : 0
                    }}
                  >
                    <Text variant="caption" weight="bold">U{i}</Text>
                  </Box>
                ))}
              </Stack>
              <Text variant="code" weight="bold">03_ONLINE</Text>
            </Stack>
          </Box>
        </Stack>
      </Box>

      <Box flex style={{ flex: 1, overflow: 'hidden' }}>
        {/* Activity Feed */}
        <Box flex direction="column" style={{ flex: 1, background: 'var(--bg)' }}>
          <Box p="md" border="bottom" borderColor="subtle" bg="surface">
            <div className="grid grid-cols-3 gap-4">
              <MetricTile label="ATTACK FREQUENCY" value="847" tone="red" isAlert />
              <MetricTile label="MITIGATION RATE" value="94%" tone="green" />
              <MetricTile label="NEW INDICATORS" value="03" tone="orange" isWarning />
            </div>
          </Box>
          
          <Box
            p="xl"
            style={{ flex: 1, overflowY: 'auto' }}
            role="log"
            aria-live="polite"
            aria-relevant="additions"
            aria-atomic="false"
            aria-label="Activity feed"
          >
            <Stack gap="xl">
              {mockActivities.map((activity) => (
                <ActivityItem key={activity.id} activity={activity} />
              ))}
            </Stack>
          </Box>

          {/* Message Input */}
          <Box p="lg" border="top" borderColor="subtle" bg="surface">
            <Stack direction="row" gap="md">
              <Box style={{ flex: 1, position: 'relative' }}>
                <Input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Transmit message to tactical channel..."
                  aria-label="War room message"
                  size="md"
                />
                <Box
                  style={{ 
                    position: 'absolute', 
                    right: 12, 
                    top: '50%', 
                    transform: 'translateY(-50%)',
                    opacity: 0.4,
                    pointerEvents: 'none'
                  }}
                >
                  <Text variant="caption" weight="bold">CTRL+ENTER</Text>
                </Box>
              </Box>
              <Button
                size="md"
                onClick={handleSendMessage}
                icon={<Send size={14} aria-hidden="true" />}
                style={{ textTransform: 'uppercase', letterSpacing: '0.2em', fontSize: '10px' }}
              >
                Transmit
              </Button>
            </Stack>
          </Box>
        </Box>

        {/* Sidebar */}
        <Box 
          style={{ width: 320 }} 
          border="left" 
          borderColor="subtle" 
          p="lg" 
          bg="surface"
        >
          <Stack gap="xl">
            {/* Playbooks */}
            <Box>
              {activePlaybook ? (
                <PlaybookRunner
                  playbook={activePlaybook}
                  onClose={() => setActivePlaybook(null)}
                  onComplete={handlePlaybookComplete}
                />
              ) : (
                <PlaybookSelector onSelect={setActivePlaybook} />
              )}
            </Box>

            {/* Live Metrics */}
            <Box>
              <Text variant="label" color="secondary" style={{ marginBottom: '16px' }}>Live Metrics</Text>
              <Stack gap="sm">
                <MetricItem label="Attack Rate" value="1,234" unit="req/min" />
                <MetricItem label="Blocked" value="892" unit="requests" />
                <MetricItem label="Affected IPs" value="47" unit="unique" />
              </Stack>
            </Box>

            {/* Customer Status */}
            <Box>
              <Text variant="label" color="secondary" style={{ marginBottom: '16px' }}>Customer Status</Text>
              <Stack gap="sm">
                <CustomerStatus name="Acme Corp" status="protected" />
                <CustomerStatus name="Globex Industries" status="protected" />
                <CustomerStatus name="Initech LLC" status="monitoring" />
              </Stack>
            </Box>
          </Stack>
        </Box>
      </Box>
    </Box>
  );
}

function ActivityItem({ activity }: { activity: Activity }) {
  const isBot = activity.actorType === 'bot';
  const isSystem = activity.actorType === 'system';
  
  const accentColor = isBot ? 'var(--ac-blue)' : isSystem ? 'var(--text-muted)' : 'var(--text)';
  const dimColor = isBot ? 'var(--ac-blue-dim)' : isSystem ? 'var(--text-dim)' : 'var(--bg-surface-subtle)';

  return (
    <Stack direction="row" gap="lg" align="start">
      <Box
        style={{
          width: 40,
          height: 40,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          border: `1px solid ${accentColor}`,
          background: dimColor,
          flexShrink: 0,
        }}
      >
        <Text variant="caption" weight="bold" style={{ color: accentColor }}>
          {isBot ? 'HB' : isSystem ? 'SY' : activity.actor.substring(0, 2).toUpperCase()}
        </Text>
      </Box>
      <Box style={{ flex: 1 }}>
        <Stack direction="row" align="center" gap="md">
          <Text variant="body" weight="bold" style={{ color: isBot ? 'var(--ac-blue)' : 'inherit' }}>
            {activity.actor}
          </Text>
          <Box
            px="xsPlus"
            py="none"
            bg="surface-inset"
            border="subtle"
          >
            <Text variant="tag" color="secondary" style={{ fontSize: '9px' }}>
              {activity.action.replaceAll('_', ' ')}
            </Text>
          </Box>
        </Stack>
        <Text variant="body" style={{ marginTop: '4px', lineHeight: '1.6' }}>
          {activity.description}
        </Text>
        <Stack direction="row" align="center" gap="sm" style={{ marginTop: '8px' }}>
          <Clock size={12} className="text-ink-muted" />
          <Text variant="caption" color="secondary" weight="bold">
            {activity.timestamp.toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            })}
          </Text>
        </Stack>
      </Box>
    </Stack>
  );
}

function MetricItem({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <Box p="md" border="subtle" bg="bg" flex direction="row" align="center" justify="space-between">
      <Text variant="label" color="secondary" style={{ fontSize: '9px' }}>{label}</Text>
      <Box style={{ textAlign: 'right' }}>
        <Text variant="body" weight="bold" inline>{value}</Text>
        <Text variant="caption" color="secondary" weight="bold" style={{ marginLeft: '6px' }}>{unit}</Text>
      </Box>
    </Box>
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
  const accentColor = `var(--ac-${tone})`;
  
  return (
    <Box 
      bg="card" 
      p="lg" 
      border="all" 
      style={{ 
        borderColor: isAlert || isWarning ? accentColor : 'var(--border-subtle)',
        boxShadow: isAlert || isWarning ? `0 0 15px color-mix(in srgb, ${accentColor}, transparent 80%)` : 'none',
        background: isAlert || isWarning ? `color-mix(in srgb, ${accentColor}, transparent 98%)` : 'var(--bg-card)'
      }}
    >
      <Text variant="label" color="secondary" style={{ marginBottom: '8px' }}>{label}</Text>
      <Stack direction="row" align="baseline" justify="space-between" gap="md">
        <Text variant="display" weight="light" noMargin style={{ color: isAlert || isWarning ? accentColor : 'inherit', fontSize: '28px' }}>
          {value}
        </Text>
        <Box
          className={isAlert || isWarning ? 'animate-pulse' : ''}
          style={{ height: 4, flex: 1, marginBottom: 6, background: accentColor }}
        />
      </Stack>
    </Box>
  );
}

function CustomerStatus({
  name,
  status,
}: {
  name: string;
  status: 'protected' | 'monitoring' | 'at-risk';
}) {
  const color = status === 'protected' ? 'var(--ac-green)' : status === 'monitoring' ? 'var(--ac-orange)' : 'var(--ac-red)';

  return (
    <Box 
      p="md" 
      border="subtle" 
      bg="bg" 
      className="hover:bg-surface-subtle transition-colors"
      flex 
      direction="row" 
      align="center" 
      justify="space-between"
    >
      <Text variant="small" weight="medium">{name}</Text>
      <Box
        px="sm"
        py="none"
        style={{
          border: '1px solid',
          background: `color-mix(in srgb, ${color}, transparent 90%)`,
          color: color,
          borderColor: `color-mix(in srgb, ${color}, transparent 70%)`,
        }}
      >
        <Text variant="tag" style={{ fontSize: '9px' }}>{status}</Text>
      </Box>
    </Box>
  );
}
