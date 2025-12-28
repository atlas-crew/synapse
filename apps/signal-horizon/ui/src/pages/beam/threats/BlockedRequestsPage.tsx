/**
 * Blocked Requests Page
 * Live feed of blocked requests with filtering and decision trace
 */

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldX,
  Search,
  Filter,
  Clock,
  MapPin,
  Target,
  AlertTriangle,
  X,
  ChevronRight,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { clsx } from 'clsx';
import { StatsGridSkeleton, TableSkeleton } from '../../../components/LoadingStates';

type BlockReason = 'sql_injection' | 'xss' | 'rate_limit' | 'bot' | 'path_traversal' | 'credential_stuffing';
type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

// Demo data - blocked requests
const DEMO_BLOCKED_REQUESTS = [
  {
    id: 'blk-001',
    timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    sourceIp: '192.168.45.102',
    method: 'POST',
    path: '/api/v1/users/search',
    reason: 'sql_injection' as BlockReason,
    riskLevel: 'critical' as RiskLevel,
    riskScore: 95,
    ruleMatched: 'SQL Injection Protection',
    userAgent: 'curl/7.64.1',
    country: 'US',
    requestSize: 1240,
    matchedPatterns: ["UNION SELECT", "' OR '1'='1"],
  },
  {
    id: 'blk-002',
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    sourceIp: '10.0.1.55',
    method: 'POST',
    path: '/api/v1/auth/login',
    reason: 'credential_stuffing' as BlockReason,
    riskLevel: 'high' as RiskLevel,
    riskScore: 82,
    ruleMatched: 'Brute Force Protection',
    userAgent: 'python-requests/2.28.0',
    country: 'CN',
    requestSize: 456,
    matchedPatterns: ['47 attempts/minute', 'known bad IP'],
  },
  {
    id: 'blk-003',
    timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
    sourceIp: '203.45.112.89',
    method: 'GET',
    path: '/api/v1/files/download',
    reason: 'path_traversal' as BlockReason,
    riskLevel: 'high' as RiskLevel,
    riskScore: 78,
    ruleMatched: 'Path Traversal Prevention',
    userAgent: 'Mozilla/5.0 (compatible)',
    country: 'RU',
    requestSize: 189,
    matchedPatterns: ['../../../etc/passwd'],
  },
  {
    id: 'blk-004',
    timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    sourceIp: '172.16.0.45',
    method: 'POST',
    path: '/api/v1/comments',
    reason: 'xss' as BlockReason,
    riskLevel: 'medium' as RiskLevel,
    riskScore: 65,
    ruleMatched: 'XSS Attack Prevention',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0)',
    country: 'BR',
    requestSize: 2340,
    matchedPatterns: ['<script>', 'onerror='],
  },
  {
    id: 'blk-005',
    timestamp: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    sourceIp: '192.168.1.100',
    method: 'GET',
    path: '/api/v1/products',
    reason: 'rate_limit' as BlockReason,
    riskLevel: 'low' as RiskLevel,
    riskScore: 35,
    ruleMatched: 'Rate Limiting - General',
    userAgent: 'Go-http-client/1.1',
    country: 'US',
    requestSize: 0,
    matchedPatterns: ['150 requests/minute (limit: 100)'],
  },
  {
    id: 'blk-006',
    timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    sourceIp: '45.67.89.123',
    method: 'GET',
    path: '/api/v1/search',
    reason: 'bot' as BlockReason,
    riskLevel: 'medium' as RiskLevel,
    riskScore: 58,
    ruleMatched: 'Bot Detection - Scraping',
    userAgent: 'Scrapy/2.6.1',
    country: 'IN',
    requestSize: 128,
    matchedPatterns: ['bot fingerprint', 'no JS execution'],
  },
  {
    id: 'blk-007',
    timestamp: new Date(Date.now() - 32 * 60 * 1000).toISOString(),
    sourceIp: '78.45.23.156',
    method: 'POST',
    path: '/api/v1/users',
    reason: 'sql_injection' as BlockReason,
    riskLevel: 'critical' as RiskLevel,
    riskScore: 92,
    ruleMatched: 'SQL Injection Protection',
    userAgent: 'sqlmap/1.6',
    country: 'DE',
    requestSize: 890,
    matchedPatterns: ['DROP TABLE', 'INSERT INTO'],
  },
  {
    id: 'blk-008',
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    sourceIp: '103.45.67.89',
    method: 'PUT',
    path: '/api/v1/profile',
    reason: 'xss' as BlockReason,
    riskLevel: 'high' as RiskLevel,
    riskScore: 75,
    ruleMatched: 'XSS Attack Prevention',
    userAgent: 'Mozilla/5.0 (Macintosh)',
    country: 'SG',
    requestSize: 1560,
    matchedPatterns: ['javascript:', 'onclick='],
  },
];

const REASON_CONFIG: Record<BlockReason, { label: string; color: string; bg: string }> = {
  sql_injection: { label: 'SQL Injection', color: 'text-red-400', bg: 'bg-red-500/20' },
  xss: { label: 'XSS Attack', color: 'text-orange-400', bg: 'bg-orange-500/20' },
  rate_limit: { label: 'Rate Limited', color: 'text-blue-400', bg: 'bg-blue-500/20' },
  bot: { label: 'Bot Detected', color: 'text-purple-400', bg: 'bg-purple-500/20' },
  path_traversal: { label: 'Path Traversal', color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  credential_stuffing: { label: 'Credential Stuffing', color: 'text-pink-400', bg: 'bg-pink-500/20' },
};

const RISK_CONFIG: Record<RiskLevel, { color: string; bg: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20' },
};

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400 bg-green-500/20',
  POST: 'text-blue-400 bg-blue-500/20',
  PUT: 'text-yellow-400 bg-yellow-500/20',
  DELETE: 'text-red-400 bg-red-500/20',
  PATCH: 'text-orange-400 bg-orange-500/20',
};

// Format relative time
function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();

  const minutes = Math.floor(diff / (1000 * 60));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// Stat Card
function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-horizon-400',
}: {
  label: string;
  value: string;
  icon: React.ElementType;
  color?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        </div>
        <div className="p-3 bg-gray-700/50 rounded-lg">
          <Icon className={clsx('w-6 h-6', color)} />
        </div>
      </div>
    </motion.div>
  );
}

// Decision Trace Modal
function DecisionTraceModal({
  request,
  onClose,
}: {
  request: (typeof DEMO_BLOCKED_REQUESTS)[0];
  onClose: () => void;
}) {
  const reasonConfig = REASON_CONFIG[request.reason];
  const riskConfig = RISK_CONFIG[request.riskLevel];

  // Demo decision trace data
  const decisionTrace = [
    { step: 1, rule: 'IP Reputation Check', result: 'pass', score: 0, detail: 'IP not in blocklist' },
    { step: 2, rule: 'Rate Limit Check', result: 'pass', score: 0, detail: 'Under threshold (100/min)' },
    { step: 3, rule: 'Bot Detection', result: 'pass', score: 5, detail: 'Low bot probability' },
    { step: 4, rule: request.ruleMatched, result: 'fail', score: request.riskScore, detail: `Matched: ${request.matchedPatterns.join(', ')}` },
  ];

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Decision Trace</h2>
              <p className="text-sm text-gray-400">Why was this request blocked?</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 overflow-y-auto max-h-[calc(80vh-120px)]">
            {/* Request Summary */}
            <div className="bg-gray-750 rounded-lg p-4 mb-6">
              <h3 className="text-sm font-medium text-gray-400 mb-3">Request Details</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-500">Endpoint</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', METHOD_COLORS[request.method])}>
                      {request.method}
                    </span>
                    <code className="text-blue-400 text-sm">{request.path}</code>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Source</p>
                  <p className="text-white mt-1 flex items-center gap-2">
                    <MapPin className="w-4 h-4 text-gray-400" />
                    {request.sourceIp} ({request.country})
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Timestamp</p>
                  <p className="text-white mt-1">{new Date(request.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">User Agent</p>
                  <p className="text-white mt-1 text-sm truncate">{request.userAgent}</p>
                </div>
              </div>
            </div>

            {/* Final Decision */}
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-start gap-3">
                <ShieldX className="w-6 h-6 text-red-400 mt-0.5" />
                <div>
                  <h3 className="text-white font-medium">Request Blocked</h3>
                  <p className="text-sm text-gray-400 mt-1">
                    Reason: <span className={clsx('font-medium', reasonConfig.color)}>{reasonConfig.label}</span>
                  </p>
                  <p className="text-sm text-gray-400">
                    Risk Score: <span className={clsx('font-medium', riskConfig.color)}>{request.riskScore}/100</span>
                  </p>
                </div>
              </div>
            </div>

            {/* Decision Trace Steps */}
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-3">Rule Evaluation Chain</h3>
              <div className="space-y-3">
                {decisionTrace.map((step, idx) => (
                  <div
                    key={step.step}
                    className={clsx(
                      'p-4 rounded-lg border',
                      step.result === 'fail'
                        ? 'bg-red-500/10 border-red-500/30'
                        : 'bg-gray-750 border-gray-700'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className={clsx(
                          'w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium',
                          step.result === 'fail' ? 'bg-red-500 text-white' : 'bg-gray-600 text-gray-300'
                        )}>
                          {step.step}
                        </span>
                        <div>
                          <p className="text-white font-medium">{step.rule}</p>
                          <p className="text-sm text-gray-400">{step.detail}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={clsx(
                          'px-2 py-0.5 rounded text-xs font-medium',
                          step.result === 'fail' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                        )}>
                          {step.result === 'fail' ? 'BLOCKED' : 'PASS'}
                        </span>
                        {step.score > 0 && (
                          <p className="text-xs text-gray-500 mt-1">+{step.score} risk</p>
                        )}
                      </div>
                    </div>
                    {idx < decisionTrace.length - 1 && step.result !== 'fail' && (
                      <div className="flex justify-center mt-2">
                        <ChevronRight className="w-4 h-4 text-gray-600 rotate-90" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Matched Patterns */}
            <div className="mt-6">
              <h3 className="text-sm font-medium text-gray-400 mb-3">Matched Patterns</h3>
              <div className="flex flex-wrap gap-2">
                {request.matchedPatterns.map((pattern, idx) => (
                  <code
                    key={idx}
                    className="px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded text-red-300 text-sm"
                  >
                    {pattern}
                  </code>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

export default function BlockedRequestsPage() {
  const [search, setSearch] = useState('');
  const [reasonFilter, setReasonFilter] = useState<string>('');
  const [selectedRequest, setSelectedRequest] = useState<(typeof DEMO_BLOCKED_REQUESTS)[0] | null>(null);
  const isLoading = false;

  // Filter requests
  const filteredRequests = useMemo(() => {
    let result = [...DEMO_BLOCKED_REQUESTS];

    if (search) {
      const term = search.toLowerCase();
      result = result.filter(
        (r) =>
          r.path.toLowerCase().includes(term) ||
          r.sourceIp.includes(term) ||
          r.ruleMatched.toLowerCase().includes(term)
      );
    }

    if (reasonFilter) {
      result = result.filter((r) => r.reason === reasonFilter);
    }

    return result;
  }, [search, reasonFilter]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = DEMO_BLOCKED_REQUESTS.length;
    const critical = DEMO_BLOCKED_REQUESTS.filter((r) => r.riskLevel === 'critical').length;
    const uniqueIps = new Set(DEMO_BLOCKED_REQUESTS.map((r) => r.sourceIp)).size;
    const avgRisk = Math.round(
      DEMO_BLOCKED_REQUESTS.reduce((sum, r) => sum + r.riskScore, 0) / total
    );

    return { total, critical, uniqueIps, avgRisk };
  }, []);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Blocked Requests</h1>
          <p className="text-gray-400 mt-1">Loading blocked requests...</p>
        </div>
        <StatsGridSkeleton />
        <TableSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Blocked Requests</h1>
          <p className="text-gray-400 mt-1">Review and analyze blocked API requests</p>
        </div>
        <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Blocked" value={stats.total.toString()} icon={ShieldX} color="text-red-400" />
        <StatCard label="Critical" value={stats.critical.toString()} icon={AlertTriangle} color="text-orange-400" />
        <StatCard label="Unique IPs" value={stats.uniqueIps.toString()} icon={MapPin} color="text-blue-400" />
        <StatCard label="Avg Risk Score" value={stats.avgRisk.toString()} icon={Target} color="text-yellow-400" />
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by path, IP, or rule..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-horizon-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={reasonFilter}
            onChange={(e) => setReasonFilter(e.target.value)}
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-horizon-500"
          >
            <option value="">All Reasons</option>
            {Object.entries(REASON_CONFIG).map(([key, config]) => (
              <option key={key} value={key}>
                {config.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Blocked Requests Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden"
      >
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-gray-400 bg-gray-800/50">
              <th className="px-5 py-3 font-medium">Time</th>
              <th className="px-5 py-3 font-medium">Source</th>
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium">Reason</th>
              <th className="px-5 py-3 font-medium">Risk</th>
              <th className="px-5 py-3 font-medium">Rule</th>
              <th className="px-5 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredRequests.map((request) => {
              const reasonConfig = REASON_CONFIG[request.reason];
              const riskConfig = RISK_CONFIG[request.riskLevel];

              return (
                <tr
                  key={request.id}
                  className="border-t border-gray-700 hover:bg-gray-750 transition-colors"
                >
                  <td className="px-5 py-4">
                    <span className="text-gray-400 text-sm flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatRelativeTime(request.timestamp)}
                    </span>
                  </td>
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-mono text-sm">{request.sourceIp}</span>
                      <span className="text-xs text-gray-500">({request.country})</span>
                    </div>
                  </td>
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-2">
                      <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', METHOD_COLORS[request.method])}>
                        {request.method}
                      </span>
                      <code className="text-blue-400 text-sm truncate max-w-[200px]">{request.path}</code>
                    </div>
                  </td>
                  <td className="px-5 py-4">
                    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', reasonConfig.bg, reasonConfig.color)}>
                      {reasonConfig.label}
                    </span>
                  </td>
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={clsx('h-full', riskConfig.bg.replace('/20', ''))}
                          style={{ width: `${request.riskScore}%` }}
                        />
                      </div>
                      <span className={clsx('text-xs font-medium', riskConfig.color)}>{request.riskScore}</span>
                    </div>
                  </td>
                  <td className="px-5 py-4">
                    <span className="text-gray-300 text-sm">{request.ruleMatched}</span>
                  </td>
                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={() => setSelectedRequest(request)}
                      className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm font-medium transition-colors inline-flex items-center gap-1"
                    >
                      <Eye className="w-4 h-4" />
                      Trace
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filteredRequests.length === 0 && (
          <div className="p-8 text-center">
            <p className="text-gray-400">No blocked requests match your filters</p>
          </div>
        )}
      </motion.div>

      {/* Decision Trace Modal */}
      {selectedRequest && (
        <DecisionTraceModal request={selectedRequest} onClose={() => setSelectedRequest(null)} />
      )}
    </div>
  );
}
