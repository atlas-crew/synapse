import { clsx } from 'clsx';
import { CheckCircle, AlertTriangle } from 'lucide-react';
import type { ApiEndpoint } from '../../hooks/useApiIntelligence';

export interface EndpointsTableProps {
  endpoints: ApiEndpoint[];
  totalCount?: number;
  isLoading?: boolean;
  emptyMessage?: string;
}

export function EndpointsTable({ endpoints, totalCount, isLoading, emptyMessage }: EndpointsTableProps) {
  return (
    <div className="card">
      <div className="card-header flex justify-between items-center">
        <h2 className="font-medium text-ink-primary">Discovered Endpoints</h2>
        {totalCount !== undefined && (
          <span className="text-xs text-ink-muted">{totalCount} total</span>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left" aria-label="Discovered API endpoints">
          <caption className="sr-only">Discovered API endpoints with risk levels and schema status</caption>
          <thead className="text-xs text-ink-muted uppercase bg-surface-subtle border-b border-border-subtle">
            <tr>
              <th className="px-4 py-3">Method</th>
              <th className="px-4 py-3">Path</th>
              <th className="px-4 py-3">Service</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Schema</th>
              <th className="px-4 py-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-ink-muted">
                  Loading endpoints...
                </td>
              </tr>
            ) : endpoints.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-8 text-ink-muted">
                  {emptyMessage || 'No endpoints discovered yet'}
                </td>
              </tr>
            ) : (
              endpoints.map((ep) => (
                <tr key={ep.id} className="hover:bg-surface-subtle transition-colors">
                  <td className="px-4 py-3 font-mono text-xs font-semibold">
                    <MethodBadge method={ep.method} />
                  </td>
                  <td className="px-4 py-3 font-mono text-ink-primary">{ep.path}</td>
                  <td className="px-4 py-3 text-ink-secondary">{ep.service}</td>
                  <td className="px-4 py-3">
                    <RiskLevelBadge riskLevel={ep.riskLevel} />
                  </td>
                  <td className="px-4 py-3">
                    <SchemaIndicator hasSchema={ep.hasSchema} />
                  </td>
                  <td className="px-4 py-3 text-ink-muted text-xs">
                    {new Date(ep.lastSeenAt).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MethodBadge({ method }: { method: string }) {
  return (
    <span
      className={clsx(
        'px-2 py-0.5',
        method === 'GET' && 'bg-ac-blue/10 text-ac-blue',
        method === 'POST' && 'bg-ac-green/10 text-ac-green',
        method === 'DELETE' && 'bg-ac-red/10 text-ac-red',
        method === 'PUT' && 'bg-ac-orange/10 text-ac-orange',
        method === 'PATCH' && 'bg-ac-purple/10 text-ac-purple'
      )}
    >
      {method}
    </span>
  );
}

function RiskLevelBadge({ riskLevel }: { riskLevel: ApiEndpoint['riskLevel'] }) {
  return (
    <span
      className={clsx(
        'px-2 py-0.5 text-xs border',
        riskLevel === 'critical' && 'bg-ac-red/10 text-ac-red border-ac-red/30',
        riskLevel === 'high' && 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
        riskLevel === 'medium' && 'bg-ac-yellow/10 text-ac-yellow border-ac-yellow/30',
        riskLevel === 'low' && 'bg-ac-blue/10 text-ac-blue border-ac-blue/30'
      )}
    >
      {riskLevel.toUpperCase()}
    </span>
  );
}

function SchemaIndicator({ hasSchema }: { hasSchema: boolean }) {
  if (hasSchema) {
    return (
      <>
        <CheckCircle className="w-4 h-4 text-ac-green" aria-hidden="true" />
        <span className="sr-only">Has schema</span>
      </>
    );
  }
  return (
    <>
      <AlertTriangle className="w-4 h-4 text-ac-orange" aria-hidden="true" />
      <span className="sr-only">Missing schema</span>
    </>
  );
}
