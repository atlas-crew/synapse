/**
 * SessionsPage — TASK-80 fleet rewiring
 *
 * Encodes the contract: the page calls fetchFleetSessions with no sensorId,
 * renders seenOnSensors as a badge per row, and surfaces stale sensors as a
 * "last seen N min ago" badge on rows whose merged data depends on a stale
 * sensor. Sensor-detail callers keep using fetchSessions separately.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import SessionsPage from '../SessionsPage';
import { fetchFleetSessions } from '../../../hooks/soc/api';
import type { SocFleetSessionListResponse } from '../../../types/soc';

vi.mock('../../../hooks/soc/api', async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, fetchFleetSessions: vi.fn() };
});

vi.mock('../../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}));

vi.mock('../../../stores/demoModeStore', () => ({
  useDemoMode: () => ({ isEnabled: false, scenario: 'normal' }),
}));

vi.mock('../../../hooks/soc/useSocSensor', () => ({
  useSocSensor: () => ({ sensorId: 'synapse-waf-1', setSensorId: vi.fn() }),
}));

const NOW = Date.UTC(2026, 3, 29, 12, 0, 0);

beforeEach(() => {
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
        <SessionsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fleetResponse(
  overrides: Partial<SocFleetSessionListResponse> = {},
): SocFleetSessionListResponse {
  return {
    aggregate: [],
    results: [],
    summary: { succeeded: 0, stale: 0, failed: 0 },
    total: 0,
    ...overrides,
  };
}

describe('SessionsPage — fleet rewiring', () => {
  it('calls fetchFleetSessions without a sensorId argument', async () => {
    vi.mocked(fetchFleetSessions).mockResolvedValue(fleetResponse());

    renderPage();

    await waitFor(() => {
      expect(fetchFleetSessions).toHaveBeenCalled();
    });
    const args = vi.mocked(fetchFleetSessions).mock.calls[0];
    expect(args).toHaveLength(1);
    expect(args[0]).toMatchObject({ limit: 50 });
  });

  it('renders the seenOnSensors count as a badge on each row', async () => {
    vi.mocked(fetchFleetSessions).mockResolvedValue(
      fleetResponse({
        aggregate: [
          {
            sessionId: 'session-multi',
            tokenHash: 'tok-session-multi',
            actorId: 'actor-a',
            creationTime: NOW - 3600 * 1000,
            lastActivity: NOW - 60 * 1000,
            requestCount: 10,
            boundJa4: null,
            boundIp: '203.0.113.10',
            isSuspicious: false,
            hijackAlerts: [],
            seenOnSensors: ['sensor-1', 'sensor-2'],
          },
        ],
        results: [
          { sensorId: 'sensor-1', status: 'ok' },
          { sensorId: 'sensor-2', status: 'ok' },
        ],
        summary: { succeeded: 2, stale: 0, failed: 0 },
        total: 1,
      }),
    );

    renderPage();

    expect((await screen.findAllByText(/2 sensors/i)).length).toBeGreaterThan(0);
  });

  it('flags rows whose merged data depends on a stale sensor', async () => {
    const eightMinAgo = new Date(NOW - 8 * 60 * 1000).toISOString();
    vi.mocked(fetchFleetSessions).mockResolvedValue(
      fleetResponse({
        aggregate: [
          {
            sessionId: 'session-stale-contributor',
            tokenHash: 'tok-stale',
            actorId: 'actor-a',
            creationTime: NOW - 3600 * 1000,
            lastActivity: NOW - 7 * 60 * 1000,
            requestCount: 14,
            boundJa4: null,
            boundIp: '203.0.113.11',
            isSuspicious: true,
            hijackAlerts: [],
            seenOnSensors: ['sensor-fresh', 'sensor-stale'],
          },
          {
            sessionId: 'session-only-fresh',
            tokenHash: 'tok-fresh',
            actorId: null,
            creationTime: NOW - 3600 * 1000,
            lastActivity: NOW - 30 * 1000,
            requestCount: 3,
            boundJa4: null,
            boundIp: '203.0.113.12',
            isSuspicious: false,
            hijackAlerts: [],
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

    expect(await screen.findByText(/8 min ago/i)).toBeInTheDocument();
    expect(screen.queryAllByText(/min ago/i)).toHaveLength(1);
  });

  it('does not render the per-sensor sensor picker input', async () => {
    vi.mocked(fetchFleetSessions).mockResolvedValue(fleetResponse());

    renderPage();

    await waitFor(() => {
      expect(fetchFleetSessions).toHaveBeenCalled();
    });
    expect(screen.queryByPlaceholderText('synapse-waf-1')).not.toBeInTheDocument();
  });
});
