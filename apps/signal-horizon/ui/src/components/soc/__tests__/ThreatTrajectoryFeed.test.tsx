import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ThreatTrajectoryFeed from '../ThreatTrajectoryFeed';
import type { Threat, ThreatAlert } from '../../../stores/horizonStore';

const mockThreats: Threat[] = [
  {
    id: 't1',
    threatType: 'SQL Injection',
    indicator: '192.168.1.1',
    riskScore: 92,
    hitCount: 450,
    tenantsAffected: 3,
    isFleetThreat: true,
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
  },
];

const mockAlerts: ThreatAlert[] = [
  {
    id: 'a1',
    type: 'campaign',
    title: 'New Campaign Detected',
    description: 'Coordinated activity from Shadow Dragon.',
    severity: 'CRITICAL',
    timestamp: Date.now(),
  },
];

describe('ThreatTrajectoryFeed', () => {
  it('renders interleaved threats and alerts', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={mockAlerts} />);
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText('New Campaign Detected')).toBeInTheDocument();
  });

  it('shows risk score and hit count for threats', () => {
    render(<ThreatTrajectoryFeed threats={mockThreats} alerts={[]} />);
    expect(screen.getByText('92%')).toBeInTheDocument();
    expect(screen.getByText('450')).toBeInTheDocument();
  });

  it('renders empty state message when no data', () => {
    render(<ThreatTrajectoryFeed threats={[]} alerts={[]} />);
    expect(screen.getByText('Awaiting signal correlation...')).toBeInTheDocument();
  });

  it('limits to 15 items', () => {
    const manyThreats = Array.from({ length: 20 }, (_, i) => ({
      ...mockThreats[0],
      id: `t${i}`,
      lastSeenAt: new Date(Date.now() - i * 1000).toISOString(),
    }));
    render(<ThreatTrajectoryFeed threats={manyThreats} alerts={[]} />);
    // Select by aria-label to get exactly the list items
    const items = screen.getAllByLabelText(/Type: threat/i);
    expect(items.length).toBeLessThanOrEqual(15);
  });
});