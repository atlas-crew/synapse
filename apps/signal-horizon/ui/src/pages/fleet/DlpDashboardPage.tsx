import { useQuery } from '@tanstack/react-query';
import { Shield, AlertTriangle, FileSearch, Search, BarChart3 } from 'lucide-react';
import { MetricCard } from '../../components/fleet';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';

const authHeaders = {
  Authorization: `Bearer ${API_KEY}`,
};

interface DlpStats {
  totalScans: number;
  totalMatches: number;
  patternCount: number;
}

interface DlpViolation {
  timestamp: number;
  pattern_name: string;
  data_type: string;
  severity: string;
  masked_value: string;
  client_ip?: string;
  path: string;
}

async function fetchDlpStats(): Promise<DlpStats> {
  const sensorId = 'synapse-pingora';
  const response = await fetch(`${API_BASE}/api/v1/synapse/${sensorId}/proxy/_sensor/dlp/stats`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch DLP stats');
  return response.json();
}

async function fetchDlpViolations(): Promise<{ violations: DlpViolation[] }> {
  const sensorId = 'synapse-pingora';
  const response = await fetch(`${API_BASE}/api/v1/synapse/${sensorId}/proxy/_sensor/dlp/violations`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch DLP violations');
  return response.json();
}

export function DlpDashboardPage() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  const { data: stats } = useQuery({
    queryKey: ['fleet', 'dlp', 'stats', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        const demoData = getDemoData(scenario);
        return demoData.fleet.dlp.stats;
      }
      return fetchDlpStats();
    },
    refetchInterval: isDemoMode ? false : 10000,
  });

  const { data: violationsData, isLoading: violationsLoading } = useQuery({
    queryKey: ['fleet', 'dlp', 'violations', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        const demoData = getDemoData(scenario);
        return { violations: demoData.fleet.dlp.violations };
      }
      return fetchDlpViolations();
    },
    refetchInterval: isDemoMode ? false : 5000,
  });

  const violations = violationsData?.violations || [];

  return (
    <div className="p-6 space-y-6 min-h-screen bg-surface-base">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Data Loss Prevention</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Monitor sensitive data leaks and fleet-wide DLP violations
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-status-success/10 border border-status-success/20 text-status-success text-xs font-bold">
          <Shield className="w-4 h-4" />
          {isDemoMode ? 'SIMULATED ENFORCEMENT' : 'ENFORCEMENT ACTIVE'}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <MetricCard label="Total Scans" value={stats?.totalScans?.toLocaleString() || '0'} description="Cumulative response bodies scanned for sensitive data patterns" />
        <MetricCard
          label="Detected Leaks"
          value={stats?.totalMatches?.toLocaleString() || '0'}
          description="Responses matching DLP patterns (e.g., SSN, credit card, API keys)"
          className={stats && stats.totalMatches > 0 ? 'border-ac-red/40 shadow-[0_0_10px_rgba(239,68,68,0.1)]' : ''}
        />
        <MetricCard label="Active Patterns" value={stats?.patternCount?.toString() || '0'} description="Number of DLP detection patterns currently enabled" />
        <MetricCard label="Avg Scan Time" value="42μs" description="Average time to scan a single response body for sensitive data" className="text-ac-blue" />
      </div>

      <div className="card shadow-lg">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-card">
          <h2 className="text-lg font-medium text-ink-primary flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-ac-red" />
            Recent Violations
          </h2>
          <div className="flex gap-2">
             <button className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle flex items-center gap-1.5 transition-colors">
               <FileSearch className="w-3.5 h-3.5" />
               Export CSV
             </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <caption className="sr-only">Data loss prevention violations with severity and source details</caption>
            <thead>
              <tr className="bg-surface-subtle/50 text-[10px] uppercase tracking-wider text-ink-muted font-bold border-b border-border-subtle">
                <th className="px-6 py-3">Timestamp</th>
                <th className="px-6 py-3">Pattern</th>
                <th className="px-6 py-3">Type</th>
                <th className="px-6 py-3">Severity</th>
                <th className="px-6 py-3">Source IP</th>
                <th className="px-6 py-3">Masked Value</th>
                <th className="px-6 py-3">Path</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {violationsLoading ? (
                <tr><td colSpan={7} className="text-center py-20 text-ink-muted">
                  <div className="animate-pulse">Loading real-time violations...</div>
                </td></tr>
              ) : violations.length === 0 ? (
                <tr><td colSpan={7} className="text-center py-20 text-ink-muted italic">
                  No sensitive data leaks detected in the last hour. Fleet is secure.
                </td></tr>
              ) : (
                violations.map((v, idx) => (
                  <tr key={idx} className="hover:bg-ac-blue/5 transition-colors group">
                    <td className="px-6 py-4 text-xs text-ink-muted font-mono">
                      {new Date(v.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 font-medium text-ink-primary">{v.pattern_name}</td>
                    <td className="px-6 py-4">
                      <span className="px-1.5 py-0.5 bg-surface-subtle border border-border-subtle text-[9px] font-bold text-ink-secondary uppercase">
                        {v.data_type}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx(
                        'px-2 py-0.5 text-[9px] font-black border uppercase tracking-tighter',
                        v.severity === 'critical' && 'bg-ac-red/10 text-ac-red border-ac-red/30',
                        v.severity === 'high' && 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
                        v.severity === 'medium' && 'bg-ac-blue/10 text-ac-blue border-ac-blue/30',
                        v.severity === 'low' && 'bg-ink-muted/10 text-ink-muted border-border-subtle'
                      )}>
                        {v.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-ink-secondary group-hover:text-ink-primary transition-colors">
                      {v.client_ip || 'Internal'}
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-ac-blue group-hover:text-ac-blue-bright transition-colors">
                      {v.masked_value}
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-xs text-ink-muted truncate max-w-[180px] font-mono" title={v.path}>
                        {v.path}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-12">
        <div className="card p-6 bg-surface-card border border-border-subtle">
          <h3 className="text-lg font-medium text-ink-primary mb-6 flex items-center gap-2">
            <Shield className="w-5 h-5 text-ac-blue" />
            Compliance Coverage
          </h3>
          <div className="space-y-6">
            <CoverageItem label="Financial (PCI-DSS)" status="Enforced" progress={100} color="bg-ac-green" />
            <CoverageItem label="Identity (PII/GDPR)" status="Enforced" progress={100} color="bg-ac-green" />
            <CoverageItem label="Secrets (API Keys/Tokens)" status="Enforced" progress={100} color="bg-ac-green" />
            <CoverageItem label="Healthcare (HIPAA)" status="Partial" progress={65} color="bg-ac-orange" />
            <CoverageItem label="Corporate IP (Custom Dictionaries)" status="Monitoring" progress={100} color="bg-ac-blue" />
          </div>
        </div>

        <div className="card p-6 bg-surface-card border border-border-subtle flex flex-col">
          <h3 className="text-lg font-medium text-ink-primary mb-6 flex items-center gap-2">
            <Search className="w-5 h-5 text-ac-purple" />
            Violation Distribution
          </h3>
          <div className="flex-1 flex items-center justify-center text-ink-muted border border-dashed border-border-subtle bg-surface-subtle/30">
             <div className="text-center">
               <BarChart3 className="w-12 h-12 mx-auto mb-3 opacity-20 text-ac-purple" />
               <p className="text-xs font-mono uppercase tracking-widest opacity-40">Classification Analytics Coming Soon</p>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CoverageItem({ label, status, progress, color }: { label: string, status: string, progress: number, color: string }) {
  return (
    <div className="space-y-2">
      <div className="flex justify-between items-end">
        <span className="text-sm text-ink-primary font-medium tracking-tight">{label}</span>
        <span className={clsx('text-[9px] font-black px-1.5 py-0.5 border uppercase', color.replace('bg-', 'text-').replace('bg-', 'border-') + '/30')}>
          {status}
        </span>
      </div>
      <div className="h-1.5 w-full bg-surface-subtle overflow-hidden border border-border-subtle/50">
        <div className={clsx('h-full transition-all duration-1000', color)} style={{ width: `${progress}%` }} />
      </div>
    </div>
  )
}