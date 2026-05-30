/**
 * SessionDetailPage — TASK-80 fleet detail rewiring
 *
 * Locks the SOC session detail view to the fleet detail endpoint and aggregate
 * response shape rather than the pre-TASK-80 per-sensor session tunnel.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import SessionDetailPage from '../SessionDetailPage';
import { fetchFleetSessionDetail, fetchSessionDetail } from '../../../hooks/soc/api';
import type { SocFleetSessionDetailResponse } from '../../../types/soc';

vi.mock('../../../hooks/soc/api', async (orig) => {
  const actual = (await orig()) as Record<string, unknown>;
  return { ...actual, fetchFleetSessionDetail: vi.fn(), fetchSessionDetail: vi.fn() };
});

vi.mock('../../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}));

vi.mock('../../../stores/demoModeStore', () => ({
  useDemoMode: () => ({ isEnabled: false, scenario: 'normal' }),
}));

const NOW = Date.UTC(2026, 3, 29, 12, 0, 0);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(NOW));
  vi.clearAllMocks();
});

function renderPage(path = '/sessions/session-1') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function detailResponse(overrides: Partial<SocFleetSessionDetailResponse> = {}): SocFleetSessionDetailResponse {
  return {
    aggregate: {
      sessionId: 'session-1',
      tokenHash: 'tok-session-1',
      actorId: 'actor-a',
      creationTime: NOW - 3600 * 1000,
      lastActivity: NOW - 60 * 1000,
      requestCount: 42,
      boundJa4: 'ja4-a',
      boundIp: '203.0.113.42',
      isSuspicious: false,
      hijackAlerts: [],
      seenOnSensors: ['sensor-1', 'sensor-2'],
    },
    results: [
      { sensorId: 'sensor-1', status: 'ok' },
      { sensorId: 'sensor-2', status: 'ok' },
    ],
    summary: { succeeded: 2, stale: 0, failed: 0 },
    ...overrides,
  };
}

describe('SessionDetailPage — fleet detail rewiring', () => {
  it('calls fetchFleetSessionDetail with the route session id and renders aggregate data', async () => {
    vi.mocked(fetchFleetSessionDetail).mockResolvedValue(detailResponse());

    renderPage();

    await waitFor(() => {
      expect(fetchFleetSessionDetail).toHaveBeenCalledWith('session-1');
    });
    expect(fetchSessionDetail).not.toHaveBeenCalled();
    expect((await screen.findAllByText('session-1')).length).toBeGreaterThan(0);
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });
});
