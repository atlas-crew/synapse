import React, { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Shield, Search, Filter, ArrowUpDown, AlertTriangle } from 'lucide-react';
import { SummaryCards, CoverageMapSummary } from './SummaryCards.js';
import { GapsPanel } from './GapsPanel.js';
import { EndpointsTable, EndpointAuthStats } from './EndpointsTable.js';
import { Button, SectionHeader, Spinner, Stack } from '@/ui';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';
const authHeaders = { 'Authorization': `Bearer ${API_KEY}` };

type RiskLevel = 'low' | 'medium' | 'high' | 'unknown';
type SortField = 'risk' | 'requests' | 'denial_rate' | 'endpoint';

interface AuthCoverageResponse {
  endpoints: EndpointAuthStats[];
  total: number;
}

async function fetchAuthCoverageSummary(): Promise<CoverageMapSummary> {
  const res = await fetch(`${API_BASE}/api/v1/auth-coverage/summary`, { headers: authHeaders });
  if (!res.ok) throw new Error('Failed to fetch summary');
  return res.json();
}

async function fetchAuthCoverage(params: {
  risk?: RiskLevel;
  sort: SortField;
}): Promise<AuthCoverageResponse> {
  const searchParams = new URLSearchParams();
  if (params.risk) searchParams.set('risk', params.risk);
  searchParams.set('sort', params.sort);

  const res = await fetch(`${API_BASE}/api/v1/auth-coverage?${searchParams}`, { headers: authHeaders });
  if (!res.ok) throw new Error('Failed to fetch endpoints');
  return res.json();
}

export const AuthCoverageMap: React.FC = () => {
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [sortBy, setSortBy] = useState<SortField>('risk');
  const [searchQuery, setSearchQuery] = useState('');
  
  const {
    data: summary,
    isLoading: summaryLoading,
    error: summaryError,
  } = useQuery({
    queryKey: ['auth-coverage-summary'],
    queryFn: fetchAuthCoverageSummary,
    refetchInterval: 30000,
  });
  
  const {
    data: endpointsData,
    isLoading: endpointsLoading,
    error: endpointsError,
  } = useQuery({
    queryKey: ['auth-coverage', riskFilter, sortBy],
    queryFn: () =>
      fetchAuthCoverage({
        risk: riskFilter === 'all' ? undefined : riskFilter,
        sort: sortBy,
      }),
    refetchInterval: 30000,
  });
  
  const filteredEndpoints = useMemo(() => {
    if (!endpointsData?.endpoints) return [];
    if (!searchQuery) return endpointsData.endpoints;
    
    const query = searchQuery.toLowerCase();
    return endpointsData.endpoints.filter((ep) =>
      ep.endpoint.toLowerCase().includes(query)
    );
  }, [endpointsData, searchQuery]);
  
  const gapEndpoints = useMemo(() => {
    return filteredEndpoints.filter(
      (ep) => ep.riskLevel === 'high' || ep.riskLevel === 'medium'
    );
  }, [filteredEndpoints]);
  
  const handleViewEndpoint = (endpoint: string) => {
    console.log('View endpoint:', endpoint);
  };
  
  if (summaryError || endpointsError) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-[400px] bg-surface-base">
        <div className="w-16 h-16 bg-danger/10 flex items-center justify-center border border-danger/30 mb-4">
          <AlertTriangle className="w-8 h-8 text-danger" />
        </div>
        <SectionHeader
          title="Error Loading Data"
          size="h4"
          mb="xs"
          style={{ marginBottom: '8px', display: 'inline-block' }}
          titleStyle={{ fontSize: '24px', lineHeight: '30px', fontWeight: 500 }}
        />
        <p className="text-ink-muted mb-6">{(summaryError || endpointsError)?.message}</p>
        <Button
          onClick={() => window.location.reload()}
          size="sm"
          style={{ padding: '0 24px' }}
        >
          Retry Connection
        </Button>
      </div>
    );
  }
  
  return (
    <div className="p-6 bg-surface-base min-h-full">
      <header className="mb-8">
        <SectionHeader
          title="Authorization Coverage Map"
          description="Real-time visibility into authentication enforcement across your fleet. Identifies shadow APIs and logical endpoints receiving authenticated traffic without enforcement."
          icon={<Shield className="w-6 h-6 text-ac-blue" />}
          size="h3"
          mb="sm"
          style={{ marginBottom: 0, maxWidth: '52rem' }}
          titleStyle={{
            fontSize: '32px',
            lineHeight: '40px',
            fontWeight: 500,
            textTransform: 'uppercase',
          }}
        />
      </header>
      
      {summaryLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8 animate-pulse">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-32 bg-surface-subtle border border-border-subtle" />
          ))}
        </div>
      ) : (
        summary && <SummaryCards summary={summary} />
      )}
      
      <div className="mb-8">
        <GapsPanel endpoints={gapEndpoints} onViewEndpoint={handleViewEndpoint} />
      </div>
      
      <section className="bg-surface-card border border-border-subtle shadow-sm">
        <Stack
          direction="column"
          justify="space-between"
          gap="md"
          className="p-4 border-b border-border-subtle md:!flex-row md:!items-center"
        >
          <SectionHeader
            title="All Observed Endpoints"
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{
              fontSize: '14px',
              lineHeight: '20px',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: '#7F7F7F',
            }}
          />
          
          <Stack direction="row" align="center" gap="md" className="flex-wrap">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-muted" />
              <input
                type="text"
                placeholder="Search endpoints..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search endpoints"
                className="pl-10 pr-4 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:ring-1 focus:ring-ac-blue/20 outline-none w-64"
              />
            </div>
            
            {/* Filter */}
            <Stack
              direction="row"
              align="center"
              gap="sm"
              className="bg-surface-base border border-border-subtle px-3 py-2"
            >
              <Filter className="w-4 h-4 text-ink-muted" />
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value as RiskLevel | 'all')}
                className="bg-transparent text-sm outline-none cursor-pointer"
              >
                <option value="all">All Risk</option>
                <option value="high">High Risk</option>
                <option value="medium">Medium Risk</option>
                <option value="low">Low Risk</option>
                <option value="unknown">No Data</option>
              </select>
            </Stack>
            
            {/* Sort */}
            <Stack
              direction="row"
              align="center"
              gap="sm"
              className="bg-surface-base border border-border-subtle px-3 py-2"
            >
              <ArrowUpDown className="w-4 h-4 text-ink-muted" />
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as SortField)}
                className="bg-transparent text-sm outline-none cursor-pointer"
              >
                <option value="risk">Sort: Risk</option>
                <option value="requests">Sort: Requests</option>
                <option value="denial_rate">Sort: Denial %</option>
                <option value="endpoint">Sort: Name</option>
              </select>
            </Stack>
          </Stack>
        </Stack>
        
        {endpointsLoading ? (
          <div className="p-12 flex flex-col items-center justify-center text-ink-muted italic bg-surface-base">
            <Spinner size={32} color="#0057B7" style={{ marginBottom: '16px' }} />
            Synchronizing endpoint catalog...
          </div>
        ) : (
          <EndpointsTable
            endpoints={filteredEndpoints}
            onSelectEndpoint={handleViewEndpoint}
          />
        )}
      </section>
    </div>
  );
};

export default AuthCoverageMap;
