import React from 'react';
import { ChevronRight } from 'lucide-react';
import { clsx } from 'clsx';
import { RiskBadge } from './RiskBadge.js';
import { PatternBadge } from './PatternBadge.js';
import { Stack } from '@/ui';

export type AuthPattern = 'enforced' | 'none_observed' | 'public' | 'insufficient_data';
export type RiskLevel = 'low' | 'medium' | 'high' | 'unknown';

export interface EndpointAuthStats {
  endpoint: string;
  method: string;
  totalRequests: number;
  denialRate: number;
  authPattern: AuthPattern;
  riskLevel: RiskLevel;
}

interface Props {
  endpoints: EndpointAuthStats[];
  onSelectEndpoint?: (endpoint: string) => void;
}

export const EndpointsTable: React.FC<Props> = ({ endpoints, onSelectEndpoint }) => {
  if (endpoints.length === 0) {
    return (
      <div className="p-12 text-center text-ink-muted italic border-t border-border-subtle bg-surface-subtle">
        No endpoints match the current filter criteria.
      </div>
    );
  }
  
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <caption className="sr-only">API endpoints with authentication coverage and risk assessment</caption>
        <thead>
          <tr className="bg-surface-subtle border-b border-border-subtle">
            <th className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-widest text-ink-muted">Logical Endpoint</th>
            <th className="px-4 py-3 text-right text-[10px] font-bold uppercase tracking-widest text-ink-muted w-32">Requests</th>
            <th className="px-4 py-3 text-right text-[10px] font-bold uppercase tracking-widest text-ink-muted w-32">Denial %</th>
            <th className="px-4 py-3 text-center text-[10px] font-bold uppercase tracking-widest text-ink-muted w-40">Auth Pattern</th>
            <th className="px-4 py-3 text-center text-[10px] font-bold uppercase tracking-widest text-ink-muted w-32">Risk Level</th>
            <th className="px-4 py-3 w-10"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle">
          {endpoints.map((ep) => (
            <tr
              key={ep.endpoint}
              className="group hover:bg-ac-blue/5 transition-colors cursor-pointer"
              onClick={() => onSelectEndpoint?.(ep.endpoint)}
            >
              <td className="px-4 py-3">
                <Stack direction="row" align="center" gap="md">
                  <span className={clsx(
                    "px-2 py-0.5  text-[10px] font-bold uppercase",
                    ep.method === 'GET' ? "bg-green-500/10 text-green-600" :
                    ep.method === 'POST' ? "bg-blue-500/10 text-blue-600" :
                    "bg-gray-500/10 text-gray-600"
                  )}>
                    {ep.method}
                  </span>
                  <span className="text-sm font-mono text-ink-primary truncate max-w-md">
                    {ep.endpoint.replace(`${ep.method} `, '')}
                  </span>
                </Stack>
              </td>
              <td className="px-4 py-3 text-right">
                <span className="text-sm font-mono text-ink-secondary">
                  {ep.totalRequests.toLocaleString()}
                </span>
              </td>
              <td className="px-4 py-3 text-right">
                <span className={clsx(
                  "text-sm font-mono font-medium",
                  ep.denialRate === 0 ? "text-danger" : "text-ink-primary"
                )}>
                  {ep.denialRate === 0 ? '0%' : `${(ep.denialRate * 100).toFixed(1)}%`}
                </span>
              </td>
              <td className="px-4 py-3 text-center">
                <PatternBadge pattern={ep.authPattern} />
              </td>
              <td className="px-4 py-3 text-center">
                <RiskBadge level={ep.riskLevel} />
              </td>
              <td className="px-4 py-3 text-right">
                <ChevronRight className="w-4 h-4 text-ink-muted group-hover:text-ac-blue transition-colors" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
