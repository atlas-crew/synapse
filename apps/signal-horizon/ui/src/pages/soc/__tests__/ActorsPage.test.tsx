/**
 * ActorsPage — TASK-99 fleet rewiring (AC#1, AC#3, AC#4)
 *
 * Encodes the contract: the page calls fetchFleetActors with no sensorId,
 * renders seenOnSensors as a badge per row, and surfaces stale sensors as a
 * "last seen N min ago" badge on rows whose merged data depends on a stale
 * sensor.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ActorsPage from '../ActorsPage';
import { fetchFleetActors } from '../../../hooks/soc/api';
import type { SocFleetActorListResponse } from '../../../types/soc';

vi.mock('../../../hooks/soc/api', async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, fetchFleetActors: vi.fn() };
});

vi.mock('../../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}));

vi.mock('../../../stores/demoModeStore', () => ({
  useDemoMode: () => ({ isEnabled: false, scenario: 'normal' }),
}));

const NOW = Date.UTC(2026, 3, 29, 12, 0, 0);

beforeEach(() => {
  // Only fake Date so relative-time formatting is deterministic. Leaving
  // setTimeout/setInterval real keeps React Query's internal scheduler working.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(NOW));
  vi.clearAllMocks();
});

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ActorsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fleetResponse(
  overrides: Partial<SocFleetActorListResponse> = {},
): SocFleetActorListResponse {
  return {
    aggregate: [],
    results: [],
    summary: { succeeded: 0, stale: 0, failed: 0 },
    total: 0,
    ...overrides,
  };
}

describe('ActorsPage — fleet rewiring', () => {
  it('calls fetchFleetActors without a sensorId argument', async () => {
    vi.mocked(fetchFleetActors).mockResolvedValue(fleetResponse());

    renderPage();

    await waitFor(() => {
      expect(fetchFleetActors).toHaveBeenCalled();
    });
    const args = vi.mocked(fetchFleetActors).mock.calls[0];
    expect(args).toHaveLength(1);
    expect(args[0]).toMatchObject({ limit: 50 });
  });

  it('renders the seenOnSensors count as a badge on each row', async () => {
    vi.mocked(fetchFleetActors).mockResolvedValue(
      fleetResponse({
        aggregate: [
          {
            actorId: 'actor-multi',
            riskScore: 80,
            ruleMatches: [],
            anomalyCount: 0,
            sessionIds: [],
            firstSeen: NOW - 3600 * 1000,
            lastSeen: NOW - 60 * 1000,
            ips: ['1.1.1.1'],
            fingerprints: ['fp-a'],
            isBlocked: false,
            seenOnSensors: ['sensor-1', 'sensor-2', 'sensor-3'],
          },
        ],
        results: [
          { sensorId: 'sensor-1', status: 'ok' },
          { sensorId: 'sensor-2', status: 'ok' },
          { sensorId: 'sensor-3', status: 'ok' },
        ],
        summary: { succeeded: 3, stale: 0, failed: 0 },
        total: 1,
      }),
    );

    renderPage();

    expect(await screen.findByText(/3 sensors/i)).toBeInTheDocument();
  });

  it('renders a "1 sensor" badge (singular) when an actor is only on one sensor', async () => {
    vi.mocked(fetchFleetActors).mockResolvedValue(
      fleetResponse({
        aggregate: [
          {
            actorId: 'actor-single',
            riskScore: 50,
            ruleMatches: [],
            anomalyCount: 0,
            sessionIds: [],
            firstSeen: NOW - 7200 * 1000,
            lastSeen: NOW - 30 * 1000,
            ips: ['2.2.2.2'],
            fingerprints: [],
            isBlocked: false,
            seenOnSensors: ['sensor-1'],
          },
        ],
        results: [{ sensorId: 'sensor-1', status: 'ok' }],
        summary: { succeeded: 1, stale: 0, failed: 0 },
        total: 1,
      }),
    );

    renderPage();

    expect(await screen.findByText(/1 sensor\b/i)).toBeInTheDocument();
  });

  it('flags rows whose merged data depends on a stale sensor with a "last seen N min ago" badge', async () => {
    const eightMinAgo = new Date(NOW - 8 * 60 * 1000).toISOString();
    vi.mocked(fetchFleetActors).mockResolvedValue(
      fleetResponse({
        aggregate: [
          {
            actorId: 'actor-stale-contributor',
            riskScore: 70,
            ruleMatches: [],
            anomalyCount: 0,
            sessionIds: [],
            firstSeen: NOW - 3600 * 1000,
            lastSeen: NOW - 7 * 60 * 1000,
            ips: ['3.3.3.3'],
            fingerprints: [],
            isBlocked: false,
            seenOnSensors: ['sensor-fresh', 'sensor-stale'],
          },
          {
            // Control row: only depends on a fresh sensor — should NOT show stale badge.
            actorId: 'actor-only-fresh',
            riskScore: 60,
            ruleMatches: [],
            anomalyCount: 0,
            sessionIds: [],
            firstSeen: NOW - 3600 * 1000,
            lastSeen: NOW - 30 * 1000,
            ips: ['4.4.4.4'],
            fingerprints: [],
            isBlocked: false,
            seenOnSensors: ['sensor-fresh'],
          },
        ],
        results: [
          { sensorId: 'sensor-fresh', status: 'ok' },
          { sensorId: 'sensor-stale', status: 'stale', lastUpdatedAt: eightMinAgo },
        ],
        summary: { succeeded: 1, stale: 1, failed: 0 },
        total: 2,
      }),
    );

    renderPage();

    // Stale row gets the badge with the lastUpdatedAt-derived relative age.
    expect(await screen.findByText(/8 min ago/i)).toBeInTheDocument();
    // Only one badge — control row remains unflagged.
    expect(screen.queryAllByText(/min ago/i)).toHaveLength(1);
  });

  it('does not render the per-sensor sensor picker input', async () => {
    vi.mocked(fetchFleetActors).mockResolvedValue(fleetResponse());

    renderPage();

    await waitFor(() => {
      expect(fetchFleetActors).toHaveBeenCalled();
    });
    expect(screen.queryByPlaceholderText('synapse-waf-1')).not.toBeInTheDocument();
  });
});
