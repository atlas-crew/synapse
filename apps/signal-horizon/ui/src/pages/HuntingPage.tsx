/**
 * Threat Hunting Page
 * Query builder, filters, results table, saved queries
 */

import { useState } from 'react';
import {
  Search,
  Filter,
  Download,
  Save,
  Clock,
  ChevronDown,
} from 'lucide-react';
import { clsx } from 'clsx';

interface SavedQuery {
  id: string;
  name: string;
  query: string;
  lastRun: Date;
}

const savedQueries: SavedQuery[] = [
  {
    id: '1',
    name: 'Cross-tenant fingerprints',
    query: 'tenantsAffected:>1 AND threatType:FINGERPRINT',
    lastRun: new Date(Date.now() - 3600000),
  },
  {
    id: '2',
    name: 'High-risk IPs',
    query: 'threatType:IP AND riskScore:>80',
    lastRun: new Date(Date.now() - 7200000),
  },
  {
    id: '3',
    name: 'Credential stuffing patterns',
    query: 'signalType:CREDENTIAL_STUFFING AND confidence:>0.9',
    lastRun: new Date(Date.now() - 86400000),
  },
];

const mockResults = [
  {
    id: '1',
    indicator: '192.168.1.100',
    type: 'IP',
    riskScore: 85,
    hits: 1523,
    tenants: 2,
    lastSeen: new Date(),
  },
  {
    id: '2',
    indicator: 'fp-dark-phoenix-001',
    type: 'FINGERPRINT',
    riskScore: 92,
    hits: 3421,
    tenants: 3,
    lastSeen: new Date(Date.now() - 600000),
  },
  {
    id: '3',
    indicator: 'AS12345',
    type: 'ASN',
    riskScore: 67,
    hits: 892,
    tenants: 1,
    lastSeen: new Date(Date.now() - 1200000),
  },
];

export default function HuntingPage() {
  const [query, setQuery] = useState('');
  const [activeFilters, setActiveFilters] = useState<string[]>([]);

  const filters = [
    { id: 'fleet', label: 'Fleet-wide only' },
    { id: 'high-risk', label: 'High risk (>80)' },
    { id: 'recent', label: 'Last 24 hours' },
  ];

  const toggleFilter = (id: string) => {
    setActiveFilters((prev) =>
      prev.includes(id) ? prev.filter((f) => f !== id) : [...prev, id]
    );
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Threat Hunting</h1>
        <p className="text-gray-400 mt-1">
          Search and analyze threats across the fleet
        </p>
      </div>

      {/* Search Bar */}
      <div className="card">
        <div className="p-4 space-y-4">
          {/* Query Input */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search threats... (e.g., threatType:IP AND riskScore:>80)"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-horizon-500 font-mono text-sm"
            />
          </div>

          {/* Filters and Actions */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-500" />
              {filters.map((filter) => (
                <button
                  key={filter.id}
                  onClick={() => toggleFilter(filter.id)}
                  className={clsx(
                    'px-3 py-1.5 text-sm rounded-lg border transition-colors',
                    activeFilters.includes(filter.id)
                      ? 'bg-horizon-600/20 border-horizon-500 text-horizon-400'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                  )}
                >
                  {filter.label}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <button className="btn-ghost">
                <Save className="w-4 h-4 mr-2" />
                Save Query
              </button>
              <button className="btn-primary">
                <Search className="w-4 h-4 mr-2" />
                Search
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-6">
        {/* Results */}
        <div className="col-span-3 card">
          <div className="card-header flex items-center justify-between">
            <h2 className="font-semibold text-white">Results</h2>
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">
                {mockResults.length} results
              </span>
              <button className="btn-ghost text-sm py-1">
                <Download className="w-4 h-4 mr-1" />
                Export
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>
                    <button className="flex items-center gap-1">
                      Indicator
                      <ChevronDown className="w-3 h-3" />
                    </button>
                  </th>
                  <th>Type</th>
                  <th>Risk Score</th>
                  <th>Hits</th>
                  <th>Tenants</th>
                  <th>Last Seen</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {mockResults.map((result) => (
                  <tr key={result.id}>
                    <td className="font-mono text-sm text-white">
                      {result.indicator}
                    </td>
                    <td>
                      <span className="px-2 py-0.5 text-xs bg-gray-700 rounded">
                        {result.type}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 rounded-full overflow-hidden bg-gray-700">
                          <div
                            className={clsx(
                              'h-full rounded-full',
                              result.riskScore >= 80 && 'bg-red-500',
                              result.riskScore >= 60 &&
                                result.riskScore < 80 &&
                                'bg-orange-500',
                              result.riskScore < 60 && 'bg-yellow-500'
                            )}
                            style={{ width: `${result.riskScore}%` }}
                          />
                        </div>
                        <span className="text-sm">{result.riskScore}</span>
                      </div>
                    </td>
                    <td>{result.hits.toLocaleString()}</td>
                    <td>{result.tenants}</td>
                    <td className="text-sm text-gray-400">
                      {result.lastSeen.toLocaleTimeString()}
                    </td>
                    <td>
                      <button className="text-sm text-red-400 hover:text-red-300">
                        Block
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Saved Queries */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-semibold text-white">Saved Queries</h2>
          </div>
          <div className="card-body space-y-2">
            {savedQueries.map((sq) => (
              <button
                key={sq.id}
                onClick={() => setQuery(sq.query)}
                className="w-full text-left p-3 bg-gray-800/50 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <div className="font-medium text-white text-sm">{sq.name}</div>
                <div className="text-xs text-gray-500 font-mono mt-1 truncate">
                  {sq.query}
                </div>
                <div className="flex items-center gap-1 mt-2 text-xs text-gray-500">
                  <Clock className="w-3 h-3" />
                  {sq.lastRun.toLocaleDateString()}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
