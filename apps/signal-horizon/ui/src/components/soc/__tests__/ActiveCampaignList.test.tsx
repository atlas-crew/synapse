import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ActiveCampaignList } from '../ActiveCampaignList';
import type { Campaign } from '../../../stores/horizonStore';

vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const now = new Date().toISOString();

const mockCampaigns: Campaign[] = [
  {
    id: '1',
    name: 'Credential Stuffing Wave',
    status: 'ACTIVE',
    severity: 'CRITICAL',
    isCrossTenant: true,
    tenantsAffected: 5,
    confidence: 0.92,
    firstSeenAt: now,
    lastActivityAt: now,
  },
  {
    id: '2',
    name: 'API Scraping Campaign',
    status: 'ACTIVE',
    severity: 'MEDIUM',
    isCrossTenant: false,
    tenantsAffected: 1,
    confidence: 0.67,
    firstSeenAt: now,
    lastActivityAt: now,
  },
];

describe('ActiveCampaignList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all campaigns with correct names', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    expect(screen.getByText('Credential Stuffing Wave')).toBeTruthy();
    expect(screen.getByText('API Scraping Campaign')).toBeTruthy();
  });

  it('applies correct severity border colors', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    const items = screen.getAllByRole('listitem');
    expect(items[0].className).toContain('border-l-ac-red');
    expect(items[1].className).toContain('border-l-ac-blue');
  });

  it('shows severity badges with correct text', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    expect(screen.getByText('CRITICAL')).toBeTruthy();
    expect(screen.getByText('MEDIUM')).toBeTruthy();
  });

  it('shows Globe icon only for cross-tenant campaigns', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    const globeIcons = screen.queryAllByLabelText('Cross-tenant campaign');
    expect(globeIcons).toHaveLength(1);
  });

  it('displays confidence percentage', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    expect(screen.getByText('92%')).toBeTruthy();
    expect(screen.getByText('67%')).toBeTruthy();
  });

  it('displays tenant count', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    expect(screen.getByText('5 tenants')).toBeTruthy();
    expect(screen.getByText('1 tenant')).toBeTruthy();
  });

  it('shows empty state when campaigns array is empty', () => {
    render(<ActiveCampaignList campaigns={[]} />);
    expect(screen.getByText('No active campaigns detected')).toBeTruthy();
    expect(screen.queryByRole('list')).toBeNull();
  });

  it('has correct ARIA attributes', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    const list = screen.getByRole('list');
    expect(list).toBeTruthy();
    expect(list.getAttribute('aria-label')).toBe('Active attack campaigns');
  });

  it('has role="listitem" on each campaign', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
  });

  it('each item has tabIndex={0} for keyboard access', () => {
    render(<ActiveCampaignList campaigns={mockCampaigns} />);
    const items = screen.getAllByRole('listitem');
    for (const item of items) {
      expect(item.getAttribute('tabindex')).toBe('0');
    }
  });
});
