import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useBeamDashboard } from './useBeamDashboard';

// Mock fetch globally
const mockFetch = vi.fn();

describe('useBeamDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset global fetch to our mock
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const mockDashboardData = {
    status: 'protected',
    summary: {
      totalEndpoints: 47,
      totalRules: 12,
      activeRules: 8,
      blocks24h: 156
    }
  };

  describe('initial state', () => {
    it('should start with null data and no error when autoFetch is disabled', () => {
      const { result } = renderHook(() => useBeamDashboard({ autoFetch: false }));

      expect(result.current.data).toBeNull();
      expect(result.current.error).toBeNull();
      expect(result.current.isConnected).toBe(false);
      expect(result.current.isLoading).toBe(false);
    });
  });

  describe('successful data fetching', () => {
    it('should fetch dashboard data successfully', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockDashboardData
      });

      const { result } = renderHook(() => useBeamDashboard({ pollingInterval: 0 }));

      await waitFor(() => {
        expect(result.current.data).not.toBeNull();
      }, { timeout: 3000 });

      expect(result.current.data?.status).toBe('protected');
      expect(result.current.error).toBeNull();
      expect(result.current.isConnected).toBe(true);
    });

    it('should call the correct API endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockDashboardData
      });

      renderHook(() => useBeamDashboard({ pollingInterval: 0 }));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/beam/dashboard'),
        expect.any(Object)
      );
    });

    it('should use custom apiBaseUrl', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockDashboardData
      });

      renderHook(() => useBeamDashboard({ apiBaseUrl: '/custom/api', pollingInterval: 0 }));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/custom/api/beam/dashboard'),
        expect.any(Object)
      );
    });
  });

  describe('error handling', () => {
    it('should fall back to demo data on network error', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const { result } = renderHook(() => useBeamDashboard({ pollingInterval: 0 }));

      await waitFor(() => {
        expect(result.current.data).not.toBeNull();
      }, { timeout: 3000 });

      // Falls back to demo data
      expect(result.current.data?.status).toBeDefined();
      expect(result.current.error).toBeTruthy();
      expect(result.current.isConnected).toBe(false);
    });

    it('should handle HTTP errors and fall back to demo', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      const { result } = renderHook(() => useBeamDashboard({ pollingInterval: 0 }));

      await waitFor(() => {
        expect(result.current.error).toBeTruthy();
      }, { timeout: 3000 });

      expect(result.current.isConnected).toBe(false);
      // Should still have demo data as fallback
      expect(result.current.data).not.toBeNull();
    });
  });

  describe('return interface', () => {
    it('should return all expected properties', () => {
      const { result } = renderHook(() => useBeamDashboard({ autoFetch: false }));

      expect(result.current).toHaveProperty('data');
      expect(result.current).toHaveProperty('isLoading');
      expect(result.current).toHaveProperty('error');
      expect(result.current).toHaveProperty('refetch');
      expect(result.current).toHaveProperty('isConnected');
      expect(result.current).toHaveProperty('lastUpdated');
      expect(typeof result.current.refetch).toBe('function');
    });
  });

  describe('data transformation', () => {
    it('should transform API response to BeamDashboard format', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockDashboardData
      });

      const { result } = renderHook(() => useBeamDashboard({ pollingInterval: 0 }));

      await waitFor(() => {
        expect(result.current.data).not.toBeNull();
      }, { timeout: 3000 });

      // Verify transformed data has expected shape
      const data = result.current.data!;
      expect(data.status).toBe('protected');
      expect(data).toHaveProperty('siteCount');
      expect(data).toHaveProperty('endpointCount');
      expect(data).toHaveProperty('activeRuleCount');
      expect(data).toHaveProperty('summary');
      expect(data).toHaveProperty('trafficTimeline');
      expect(data).toHaveProperty('attackTypes');
    });
  });
});
