/**
 * useApexThreats Hook
 * Fetches blocked requests and threat activity from Signal Horizon API
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import type { BlockedRequest, AttackPattern, ThreatEvent } from '../types/apex';

// ============================================================================
// API Response Types
// ============================================================================

interface ThreatsApiResponse {
  blocks: ApiBlockDecision[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}

interface ApiBlockDecision {
  id: string;
  action: string;
  severity: string;
  threatType: string;
  sourceIp: string;
  path: string;
  method: string;
  ruleId?: string;
  riskScore: number;
  decidedAt: string;
  sensor?: { id: string; name: string };
}

interface BlockDetailResponse {
  block: ApiBlockDecision & {
    sensor?: { id: string; name: string; version: string };
  };
}

// ============================================================================
// Hook Configuration
// ============================================================================

export type ThreatTimeRange = '1h' | '6h' | '24h' | '7d' | '30d';
export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatStatus = 'blocked' | 'challenged' | 'throttled' | 'logged';

export interface ThreatQueryParams {
  severity?: ThreatSeverity;
  status?: ThreatStatus;
  timeRange?: ThreatTimeRange;
  limit?: number;
  offset?: number;
}

export interface UseApexThreatsOptions {
  /** Polling interval in milliseconds (default: 15000 = 15s for real-time feel) */
  pollingInterval?: number;
  /** Whether to start fetching immediately (default: true) */
  autoFetch?: boolean;
  /** API base URL (default: /api/v1) */
  apiBaseUrl?: string;
  /** Query parameters for filtering */
  queryParams?: ThreatQueryParams;
}

export interface UseApexThreatsResult {
  blocks: BlockedRequest[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
  attackPatterns: AttackPattern[];
  recentEvents: ThreatEvent[];
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  fetchBlockById: (id: string) => Promise<BlockedRequest | null>;
  loadMore: () => Promise<void>;
  isConnected: boolean;
  lastUpdated: Date | null;
  // Computed stats
  stats: {
    total: number;
    blocked: number;
    challenged: number;
    criticalCount: number;
    highCount: number;
  };
}

// ============================================================================
// Demo Data Generator
// ============================================================================

function generateDemoBlocks(): BlockedRequest[] {
  const actions = ['blocked', 'challenged', 'throttled', 'logged'] as const;
  const threatTypes = ['SQL_INJECTION', 'XSS', 'BOT_TRAFFIC', 'BRUTE_FORCE', 'SCRAPING', 'CREDENTIAL_STUFFING'];
  const methods = ['GET', 'POST', 'PUT', 'DELETE'];
  const endpoints = [
    '/api/v2/users',
    '/api/v2/auth/login',
    '/api/v2/products',
    '/api/v2/cart',
    '/api/v2/orders',
    '/api/v2/payments',
  ];

  return Array.from({ length: 100 }, (_, i) => ({
    id: `block-${i + 1}`,
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
    action: actions[Math.floor(Math.random() * actions.length)],
    threatType: threatTypes[Math.floor(Math.random() * threatTypes.length)],
    sourceIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    endpoint: endpoints[Math.floor(Math.random() * endpoints.length)],
    method: methods[Math.floor(Math.random() * methods.length)],
    ruleId: `rule-${Math.floor(Math.random() * 5) + 1}`,
    ruleName: `Protection Rule ${Math.floor(Math.random() * 5) + 1}`,
    riskScore: Math.floor(Math.random() * 100),
  }));
}

function generateDemoPatterns(): AttackPattern[] {
  return [
    { type: 'SQL_INJECTION', count: 847, percentage: 29.7, trend: 12.5 },
    { type: 'BOT_TRAFFIC', count: 721, percentage: 25.3, trend: -5.2 },
    { type: 'XSS', count: 534, percentage: 18.8, trend: 8.7 },
    { type: 'BRUTE_FORCE', count: 398, percentage: 14.0, trend: 15.3 },
    { type: 'SCRAPING', count: 347, percentage: 12.2, trend: -2.1 },
  ];
}

// ============================================================================
// Hook Implementation
// ============================================================================

export function useApexThreats(options: UseApexThreatsOptions = {}): UseApexThreatsResult {
  const {
    pollingInterval = 15000, // 15s for near-real-time threat monitoring
    autoFetch = true,
    apiBaseUrl = '/api/v1',
    queryParams = {},
  } = options;

  const [blocks, setBlocks] = useState<BlockedRequest[]>([]);
  const [pagination, setPagination] = useState({
    total: 0,
    limit: queryParams.limit || 50,
    offset: queryParams.offset || 0,
    hasMore: false,
  });
  const [attackPatterns] = useState<AttackPattern[]>(generateDemoPatterns());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const intervalRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Transform API block to UI BlockedRequest
  const transformBlock = useCallback((apiBlock: ApiBlockDecision): BlockedRequest => ({
    id: apiBlock.id,
    timestamp: apiBlock.decidedAt,
    action: apiBlock.action as BlockedRequest['action'],
    threatType: apiBlock.threatType,
    sourceIp: apiBlock.sourceIp,
    endpoint: apiBlock.path,
    method: apiBlock.method,
    ruleId: apiBlock.ruleId,
    riskScore: apiBlock.riskScore,
  }), []);

  const fetchData = useCallback(async (append = false) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsLoading(true);

    try {
      const params = new URLSearchParams();
      if (queryParams.severity) params.set('severity', queryParams.severity);
      if (queryParams.status) params.set('status', queryParams.status);
      if (queryParams.timeRange) params.set('timeRange', queryParams.timeRange);
      params.set('limit', (queryParams.limit || 50).toString());
      params.set('offset', (append ? pagination.offset + pagination.limit : queryParams.offset || 0).toString());

      const url = `${apiBaseUrl}/apex/threats?${params}`;

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as ThreatsApiResponse;
      const transformedBlocks = data.blocks.map(transformBlock);

      if (append) {
        setBlocks(prev => [...prev, ...transformedBlocks]);
      } else {
        setBlocks(transformedBlocks);
      }

      setPagination(data.pagination);
      setIsConnected(true);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;

      console.warn('Failed to fetch apex threats, using demo data:', err);
      setError(err as Error);
      setIsConnected(false);

      if (blocks.length === 0) {
        const demoBlocks = generateDemoBlocks();
        setBlocks(demoBlocks);
        setPagination({ total: demoBlocks.length, limit: 50, offset: 0, hasMore: false });
      }
    } finally {
      setIsLoading(false);
    }
  }, [apiBaseUrl, queryParams, transformBlock, pagination, blocks.length]);

  const loadMore = useCallback(async () => {
    if (pagination.hasMore && !isLoading) {
      await fetchData(true);
    }
  }, [pagination.hasMore, isLoading, fetchData]);

  const fetchBlockById = useCallback(async (id: string): Promise<BlockedRequest | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/apex/threats/${id}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json() as BlockDetailResponse;
      return transformBlock(data.block);
    } catch (err) {
      console.warn('Failed to fetch block details:', err);
      return null;
    }
  }, [apiBaseUrl, transformBlock]);

  // Derive recent events from blocks
  const recentEvents = useMemo<ThreatEvent[]>(() =>
    blocks.slice(0, 10).map(block => ({
      id: block.id,
      timestamp: block.timestamp,
      type: block.threatType,
      sourceIp: block.sourceIp,
      action: block.action,
      rule: block.ruleName,
    })),
  [blocks]);

  // Computed stats
  const stats = useMemo(() => ({
    total: pagination.total,
    blocked: blocks.filter(b => b.action === 'blocked').length,
    challenged: blocks.filter(b => b.action === 'challenged').length,
    criticalCount: blocks.filter(b => b.riskScore >= 80).length,
    highCount: blocks.filter(b => b.riskScore >= 60 && b.riskScore < 80).length,
  }), [blocks, pagination.total]);

  useEffect(() => {
    if (autoFetch) fetchData();
    return () => { abortControllerRef.current?.abort(); };
  }, [autoFetch]); // Note: deliberately not including fetchData to avoid refetch on queryParams change

  // Refetch when query params change
  useEffect(() => {
    if (autoFetch) fetchData();
  }, [queryParams.severity, queryParams.status, queryParams.timeRange]);

  useEffect(() => {
    if (pollingInterval > 0) {
      intervalRef.current = window.setInterval(() => fetchData(false), pollingInterval);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [pollingInterval]);

  return {
    blocks,
    pagination,
    attackPatterns,
    recentEvents,
    isLoading,
    error,
    refetch: () => fetchData(false),
    fetchBlockById,
    loadMore,
    isConnected,
    lastUpdated,
    stats,
  };
}

export default useApexThreats;
