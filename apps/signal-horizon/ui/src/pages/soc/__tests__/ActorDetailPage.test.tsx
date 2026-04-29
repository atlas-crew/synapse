/**
 * ActorDetailPage — TASK-99 fleet rewiring (AC#2, AC#4)
 *
 * Encodes the contract: detail + timeline use the fleet hooks (no sensorId),
 * the header surfaces seenOnSensors and a "stale data" indicator when any
 * contributing sensor reports stale, and timeline events carry sensor
 * attribution.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ActorDetailPage from '../ActorDetailPage';
import {
  fetchFleetActorDetail,
  fetchFleetActorTimeline,
} from '../../../hooks/soc/api';
import type {
  SocFleetActorDetailResponse,
  SocFleetActorTimelineResponse,
} from '../../../types/soc';

vi.mock('../../../hooks/soc/api', async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return {
    ...actual,
    fetchFleetActorDetail: vi.fn(),
    fetchFleetActorTimeline: vi.fn(),
  };
});

vi.mock('../../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}));

vi.mock('../../../stores/demoModeStore', () => ({
  useDemoMode: () => ({ isEnabled: false, scenario: 'normal' }),
}));

vi.mock('../../../hooks/soc/useSocWatchlist', () => ({
  useSocWatchlist: () => ({
    isWatched: () => false,
    toggleWatch: vi.fn(),
  }),
}));

const NOW = Date.UTC(2026, 3, 29, 12, 0, 0);

beforeEach(() => {
  // Only fake Date so relative-time formatting is deterministic. Leaving
  // setTimeout/setInterval real keeps React Query's internal scheduler working.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(NOW));
  vi.clearAllMocks();
});

function renderAt(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/actors/:id" element={<ActorDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function detailResponse(
  overrides: Partial<SocFleetActorDetailResponse> = {},
): SocFleetActorDetailResponse {
  return {
    aggregate: {
      actorId: 'actor-x',
      riskScore: 70,
      ruleMatches: [],
      anomalyCount: 0,
      sessionIds: ['s-1'],
      firstSeen: NOW - 3600 * 1000,
      lastSeen: NOW - 60 * 1000,
      ips: ['1.1.1.1'],
      fingerprints: ['fp-a'],
      isBlocked: false,
      seenOnSensors: ['sensor-1'],
    },
    results: [{ sensorId: 'sensor-1', status: 'ok' }],
    summary: { succeeded: 1, stale: 0, failed: 0 },
    ...overrides,
  };
}

function timelineResponse(
  overrides: Partial<SocFleetActorTimelineResponse> = {},
): SocFleetActorTimelineResponse {
  return {
    aggregate: { actorId: 'actor-x', events: [] },
    results: [{ sensorId: 'sensor-1', status: 'ok' }],
    summary: { succeeded: 1, stale: 0, failed: 0 },
    ...overrides,
  };
}

describe('ActorDetailPage — fleet rewiring', () => {
  it('calls fetchFleetActorDetail and fetchFleetActorTimeline without a sensorId', async () => {
    vi.mocked(fetchFleetActorDetail).mockResolvedValue(detailResponse());
    vi.mocked(fetchFleetActorTimeline).mockResolvedValue(timelineResponse());

    renderAt('/actors/actor-x');

    await waitFor(() => {
      expect(fetchFleetActorDetail).toHaveBeenCalled();
    });

    expect(fetchFleetActorDetail).toHaveBeenCalledWith('actor-x');
    expect(fetchFleetActorTimeline).toHaveBeenCalledWith('actor-x', expect.any(Number));
  });

  it('renders the seenOnSensors count in the header', async () => {
    vi.mocked(fetchFleetActorDetail).mockResolvedValue(
      detailResponse({
        aggregate: {
          ...detailResponse().aggregate,
          seenOnSensors: ['sensor-1', 'sensor-2', 'sensor-3'],
        },
      }),
    );
    vi.mocked(fetchFleetActorTimeline).mockResolvedValue(timelineResponse());

    renderAt('/actors/actor-x');

    expect(await screen.findByText(/3 sensors/i)).toBeInTheDocument();
  });

  it('shows a stale-data indicator when summary.stale > 0', async () => {
    vi.mocked(fetchFleetActorDetail).mockResolvedValue(
      detailResponse({
        results: [
          { sensorId: 'sensor-fresh', status: 'ok' },
          {
            sensorId: 'sensor-stale',
            status: 'stale',
            lastUpdatedAt: new Date(NOW - 11 * 60 * 1000).toISOString(),
          },
        ],
        summary: { succeeded: 1, stale: 1, failed: 0 },
      }),
    );
    vi.mocked(fetchFleetActorTimeline).mockResolvedValue(timelineResponse());

    renderAt('/actors/actor-x');

    expect(await screen.findByText(/stale data/i)).toBeInTheDocument();
    expect(await screen.findByText(/11 min ago/i)).toBeInTheDocument();
  });

  it('renders timeline events with their sensor attribution', async () => {
    vi.mocked(fetchFleetActorDetail).mockResolvedValue(detailResponse());
    vi.mocked(fetchFleetActorTimeline).mockResolvedValue(
      timelineResponse({
        aggregate: {
          actorId: 'actor-x',
          events: [
            { sensorId: 'sensor-east', timestamp: NOW - 1000, eventType: 'rule_match', ruleId: 'r-1' },
            { sensorId: 'sensor-west', timestamp: NOW - 2000, eventType: 'block', clientIp: '1.1.1.1' },
          ],
        },
      }),
    );

    renderAt('/actors/actor-x');

    expect(await screen.findByText('sensor-east')).toBeInTheDocument();
    expect(await screen.findByText('sensor-west')).toBeInTheDocument();
  });
});
