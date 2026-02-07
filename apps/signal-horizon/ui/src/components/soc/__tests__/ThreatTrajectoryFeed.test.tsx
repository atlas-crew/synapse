import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ThreatTrajectoryFeed } from '../ThreatTrajectoryFeed';
import type { Threat, ThreatAlert } from '../../../stores/horizonStore';

vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const baseTime = Date.now();

const mockThreats: Threat[] = [
  {
    id: 't1',
    threatType: 'ip_reputation',
    indicator: '185.228.101.42',
    riskScore: 85,
    hitCount: 1240,
    tenantsAffected: 3,
    isFleetThreat: true,
    firstSeenAt: new Date(baseTime - 3600000).toISOString(),
    lastSeenAt: new Date(baseTime - 1000).toISOString(),
  },
  {
    id: 't2',
    threatType: 'bot_signature',
    indicator: 'bot-fp-abc123',
    riskScore: 45,
    hitCount: 320,
    tenantsAffected: 1,
    isFleetThreat: false,
    firstSeenAt: new Date(baseTime - 7200000).toISOString(),
    lastSeenAt: new Date(baseTime - 60000).toISOString(),
  },
];

const mockAlerts: ThreatAlert[] = [
  {
    id: 'a1',
    type: 'campaign',
    title: 'New campaign detected',
    description: 'Credential stuffing from AS12345',
    severity: 'HIGH',
    timestamp: baseTime - 5000,
  },
  {
    id: 'a2',
    type: 'threat',
    title: 'Risk threshold exceeded',
    description: 'IP block rate above 90%',
    severity: 'CRITICAL',
    timestamp: baseTime - 120000,
  },
];

describe('ThreatTrajectoryFeed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders threats and alerts merged in timestamp order', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={mockAlerts} />);

    expect(screen.getByText('185.228.101.42')).toBeTruthy();
    expect(screen.getByText('bot-fp-abc123')).toBeTruthy();
    expect(screen.getByText('New campaign detected')).toBeTruthy();
    expect(screen.getByText('Risk threshold exceeded')).toBeTruthy();

    // Verify order: newest first
    const container = screen.getByRole('log');
    const text = container.textContent ?? '';
    const t1Pos = text.indexOf('185.228.101.42');
    const a1Pos = text.indexOf('New campaign detected');
    const t2Pos = text.indexOf('bot-fp-abc123');
    const a2Pos = text.indexOf('Risk threshold exceeded');
    expect(t1Pos).toBeLessThan(a1Pos);
    expect(a1Pos).toBeLessThan(t2Pos);
    expect(t2Pos).toBeLessThan(a2Pos);
  });

  it('shows max 15 items when given more data', () => {
    const manyThreats: Threat[] = Array.from({ length: 20 }, (_, i) => ({
      id: `t-bulk-${i}`,
      threatType: 'ip_reputation',
      indicator: `10.0.0.${i}`,
      riskScore: 50 + i,
      hitCount: 100,
      tenantsAffected: 1,
      isFleetThreat: false,
      firstSeenAt: new Date(baseTime - 100000).toISOString(),
      lastSeenAt: new Date(baseTime - i * 1000).toISOString(),
    }));

    render(<ThreatTrajectoryFeed threats={manyThreats} alerts={[]} />);

    for (let i = 0; i < 15; i++) {
      expect(screen.getByText(`10.0.0.${i}`)).toBeTruthy();
    }
    for (let i = 15; i < 20; i++) {
      expect(screen.queryByText(`10.0.0.${i}`)).toBeNull();
    }
  });

  it('displays threat indicator and risk score', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={[]} />);
    expect(screen.getByText('185.228.101.42')).toBeTruthy();
    expect(screen.getByText(/Risk: 85/)).toBeTruthy();
  });

  it('displays alert title and description', () => {
    render(<ThreatTrajectoryFeed threats={[]} alerts={mockAlerts} />);
    expect(screen.getByText('New campaign detected')).toBeTruthy();
    expect(screen.getByText('Credential stuffing from AS12345')).toBeTruthy();
  });

  it('shows FLEET tag for fleet threats', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={[]} />);
    const fleetTags = screen.queryAllByText('FLEET');
    expect(fleetTags).toHaveLength(1);
  });

  it('does not show FLEET for non-fleet threats', () => {
    const nonFleet: Threat[] = [{ ...mockThreats[1], isFleetThreat: false }];
    render(<ThreatTrajectoryFeed threats={nonFleet} alerts={[]} />);
    expect(screen.queryByText('FLEET')).toBeNull();
  });

  it('shows empty state when both arrays are empty', () => {
    render(<ThreatTrajectoryFeed threats={[]} alerts={[]} />);
    expect(screen.getByText('No threat activity detected')).toBeTruthy();
  });

  it('has correct ARIA attributes', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={mockAlerts} />);
    const log = screen.getByRole('log');
    expect(log).toBeTruthy();
    expect(log.getAttribute('aria-live')).toBe('polite');
    expect(log.getAttribute('aria-label')).toBe('Threat trajectory feed');
  });

  it('renders <time> elements with dateTime for threats', () => {
    render(<ThreatTrajectoryFeed threats={[mockThreats[0]]} alerts={[]} />);
    const timeEls = document.querySelectorAll('time');
    expect(timeEls.length).toBeGreaterThanOrEqual(1);
    expect(timeEls[0].getAttribute('datetime')).toBeTruthy();
  });

  it('renders <time> elements with dateTime for alerts', () => {
    render(<ThreatTrajectoryFeed threats={[]} alerts={[mockAlerts[0]]} />);
    const timeEls = document.querySelectorAll('time');
    expect(timeEls.length).toBeGreaterThanOrEqual(1);
    const expectedIso = new Date(mockAlerts[0].timestamp).toISOString();
    expect(timeEls[0].getAttribute('datetime')).toBe(expectedIso);
  });
});
