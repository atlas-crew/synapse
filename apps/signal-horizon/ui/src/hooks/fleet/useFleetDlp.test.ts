import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createElement, type ReactNode } from 'react';
import { useFleetDlp } from './useFleetDlp';
import { ApiError, apiFetch } from '../../lib/api';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

vi.mock('../../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/api')>();
  return {
    ...actual,
    apiFetch: vi.fn(),
  };
});

vi.mock('../../stores/demoModeStore', () => ({
  useDemoMode: vi.fn(),
}));

vi.mock('../../lib/demoData', () => ({
  getDemoData: vi.fn(),
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe('useFleetDlp', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useDemoMode).mockReturnValue({
      isEnabled: false,
      scenario: 'normal',
      tick: 0,
    } as unknown as ReturnType<typeof useDemoMode>);
  });

  it('maps the partial-results envelope into aggregate data plus degraded-state metadata', async () => {
    vi.mocked(apiFetch)
      .mockResolvedValueOnce({
        aggregate: { totalScans: 140, totalMatches: 3, patternCount: 25 },
        results: [
          { sensorId: 'sensor-1', status: 'ok', data: { totalScans: 100, totalMatches: 2, patternCount: 25 } },
          { sensorId: 'sensor-2', status: 'error', error: 'No payload snapshot available' },
        ],
        summary: { succeeded: 1, failed: 1 },
      })
      .mockResolvedValueOnce({
        aggregate: [
          {
            timestamp: 1700000000000,
            pattern_name: 'Visa Card',
            data_type: 'credit_card',
            severity: 'critical',
            masked_value: '****-****-****-4242',
            path: '/checkout',
            sensorId: 'sensor-1',
            sensorName: 'edge-east',
          },
        ],
        results: [
          { sensorId: 'sensor-1', status: 'ok', data: [] },
          { sensorId: 'sensor-2', status: 'error', error: 'No payload snapshot available' },
        ],
        summary: { succeeded: 1, failed: 1 },
      });

    const { result } = renderHook(() => useFleetDlp(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.data?.stats.totalScans).toBe(140);
    });

    expect(result.current.data).toMatchObject({
      stats: { totalScans: 140, totalMatches: 3, patternCount: 25 },
      partial: {
        succeeded: 1,
        failed: 1,
        failedSensorIds: ['sensor-2'],
      },
    });
    expect(result.current.data?.violations).toEqual([
      expect.objectContaining({
        sensorId: 'sensor-1',
        sensorName: 'edge-east',
        pattern_name: 'Visa Card',
      }),
    ]);
  });

  it('returns typed demo data without reporting partial failures', async () => {
    vi.mocked(useDemoMode).mockReturnValue({
      isEnabled: true,
      scenario: 'normal',
      tick: 0,
    } as unknown as ReturnType<typeof useDemoMode>);
    vi.mocked(getDemoData).mockReturnValue({
      fleet: {
        dlp: {
          stats: { totalScans: 10, totalMatches: 1, patternCount: 2 },
          violations: [
            {
              timestamp: 1700000000000,
              pattern_name: 'SSN',
              data_type: 'pii',
              severity: 'high',
              masked_value: '***-**-1234',
              client_ip: '203.0.113.10',
              path: '/api/export',
              sensorId: 'demo-sensor',
              sensorName: 'Demo Sensor',
            },
          ],
        },
      },
    } as unknown as ReturnType<typeof getDemoData>);

    const { result } = renderHook(() => useFleetDlp(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.data?.stats.totalScans).toBe(10);
    });

    expect(result.current.data).toMatchObject({
      partial: {
        succeeded: 1,
        failed: 0,
        failedSensorIds: [],
      },
      violations: [
        expect.objectContaining({
          sensorId: 'demo-sensor',
          sensorName: 'Demo Sensor',
          pattern_name: 'SSN',
        }),
      ],
    });
    expect(apiFetch).not.toHaveBeenCalled();
  });

  it('surfaces API failures through the query error state', async () => {
    vi.mocked(apiFetch).mockRejectedValueOnce(
      new ApiError(503, '503 Service Unavailable: No sensors reported a usable DLP snapshot')
    );

    const { result } = renderHook(() => useFleetDlp(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).toBeInstanceOf(ApiError);
    expect(result.current.data).toBeUndefined();
  });
});
